//! Recusa, no kernel, que uma aplicação abra porta fixa acessível de fora.
//!
//! O netguard olha depois: varre os sockets a cada 15s e derruba quem estiver
//! exposto. Pelo `/proc` não dá para separar um serviço UDP (o app escolheu o
//! endereço com `bind()`) de um cliente UDP (o kernel deu uma porta efêmera no
//! primeiro envio) — os dois aparecem como `0.0.0.0:porta`, sem conexão. Tratar
//! todo UDP como serviço derrubava clientes legítimos; tratar porta efêmera
//! como cliente seria adivinhar.
//!
//! A diferença real está no momento em que o endereço é escolhido, e o kernel
//! tem um gancho exatamente ali: um programa BPF de cgroup (`bind4`/`bind6`)
//! que roda em toda chamada `bind()` explícita. Preso ao `selynt.slice`, vale
//! para todo processo de toda aplicação, inclusive as que já estão no ar.
//!
//! A regra:
//! - endereço de loopback, qualquer porta: passa — o app pode falar consigo;
//! - porta 0, qualquer endereço: passa — é o kernel quem escolhe a porta. O
//!   resolvedor da musl e o `dgram` do Node fazem `bind(:: / 0.0.0.0, 0)`
//!   explícito antes de enviar, e recusar isso quebraria DNS e UDP de cliente;
//! - endereço não-loopback com porta fixa: `EPERM`. É o que define um serviço.
//!
//! O que fica possível, e é da natureza do UDP: um socket que envia recebe de
//! volta na porta que ganhou, de qualquer origem. Isso vale para todo cliente
//! de rede, DNS incluído, e não há como fechar sem quebrá-lo.
//!
//! O que este gancho não vê é `listen()` TCP sem `bind()` (o kernel escolhe a
//! porta) — esse caso continua com o netguard, cuja regra TCP já é precisa.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

#[cfg(not(target_endian = "little"))]
compile_error!("os programas leem endereços como u32 little-endian");

/// O cgroup que contém todas as aplicações: `selynt.slice/selynt-<conta>.slice/
/// selynt-<conta>-<app>.scope`.
pub const SLICE_UNIT: &str = "selynt.slice";
const SLICE_CGROUP: &str = "/sys/fs/cgroup/selynt.slice";

/// Nomes dos programas no kernel, pelos quais a consulta os reconhece.
const NAME_V4: &str = "selynt_bind4";
const NAME_V6: &str = "selynt_bind6";

// Constantes da uapi do kernel (`include/uapi/linux/bpf.h`).
const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_PROG_ATTACH: libc::c_long = 8;
const BPF_PROG_DETACH: libc::c_long = 9;
const BPF_PROG_GET_FD_BY_ID: libc::c_long = 13;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;
const BPF_PROG_QUERY: libc::c_long = 16;
const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
const BPF_CGROUP_INET4_BIND: u32 = 8;
const BPF_CGROUP_INET6_BIND: u32 = 9;

/// Deslocamentos em `struct bpf_sock_addr`, o contexto do gancho.
const CTX_USER_IP4: i16 = 4;
const CTX_USER_IP6: i16 = 8;
const CTX_USER_PORT: i16 = 24;

/// Uma instrução BPF, codificada como o kernel a lê.
#[derive(Clone, Copy)]
struct Insn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

impl Insn {
    const fn bytes(self) -> [u8; 8] {
        let off = self.off.to_le_bytes();
        let imm = self.imm.to_le_bytes();
        [
            self.code, self.regs, off[0], off[1], imm[0], imm[1], imm[2], imm[3],
        ]
    }
}

// Opcodes usados. JMP32 compara só os 32 bits baixos: com JMP de 64 bits, um
// imediato como 0xffff0000 seria estendido com sinal e nunca casaria com o
// valor de 32 bits lido do contexto.
const LDX_W: u8 = 0x61; // r_dst = *(u32 *)(r_src + off)
const JEQ32_K: u8 = 0x16; // if w_dst == imm goto +off
const JNE32_K: u8 = 0x56; // if w_dst != imm goto +off
const AND64_K: u8 = 0x57; // r_dst &= imm
const MOV64_K: u8 = 0xb7; // r_dst = imm
const JA: u8 = 0x05; // goto +off
const EXIT: u8 = 0x95;

/// `r2 = *(u32 *)(ctx + off)`, com o contexto em r1.
const fn load(off: i16) -> Insn {
    Insn {
        code: LDX_W,
        regs: 0x12,
        off,
        imm: 0,
    }
}
const fn jeq(imm: i32, off: i16) -> Insn {
    Insn {
        code: JEQ32_K,
        regs: 0x02,
        off,
        imm,
    }
}
const fn jne(imm: i32, off: i16) -> Insn {
    Insn {
        code: JNE32_K,
        regs: 0x02,
        off,
        imm,
    }
}
const fn and(imm: i32) -> Insn {
    Insn {
        code: AND64_K,
        regs: 0x02,
        off: 0,
        imm,
    }
}
const fn ret(v: i32) -> Insn {
    Insn {
        code: MOV64_K,
        regs: 0x00,
        off: 0,
        imm: v,
    }
}
const fn goto(off: i16) -> Insn {
    Insn {
        code: JA,
        regs: 0,
        off,
        imm: 0,
    }
}
const EXIT_INSN: Insn = Insn {
    code: EXIT,
    regs: 0,
    off: 0,
    imm: 0,
};

/// Primeiro octeto 127, lido de um u32 little-endian em ordem de rede.
const LOOPBACK_OCTET: i32 = 127;
/// `::1` na última palavra: bytes `00 00 00 01`.
const IP6_LAST_WORD_ONE: i32 = 0x0100_0000;
/// `::ffff:` na terceira palavra: bytes `00 00 ff ff`.
#[allow(clippy::cast_possible_wrap)]
const IP6_V4_MAPPED: i32 = 0xffff_0000_u32 as i32;

/// `bind()` IPv4: 1 deixa passar, 0 recusa com `EPERM`.
const PROG_V4: [Insn; 9] = [
    load(CTX_USER_PORT),    // 0
    jeq(0, 5),              // 1: porta 0 → 7
    load(CTX_USER_IP4),     // 2
    and(0xff),              // 3: primeiro octeto
    jeq(LOOPBACK_OCTET, 2), // 4: 127/8 → 7
    ret(0),                 // 5
    EXIT_INSN,              // 6
    ret(1),                 // 7
    EXIT_INSN,              // 8
];

/// `bind()` IPv6: loopback é `::1` ou `::ffff:127.x.x.x`.
const PROG_V6: [Insn; 19] = [
    load(CTX_USER_PORT),       // 0
    jeq(0, 15),                // 1: porta 0 → 17
    load(CTX_USER_IP6),        // 2
    jne(0, 11),                // 3: → 15
    load(CTX_USER_IP6 + 4),    // 4
    jne(0, 9),                 // 5: → 15
    load(CTX_USER_IP6 + 8),    // 6
    jeq(IP6_V4_MAPPED, 4),     // 7: ::ffff:a.b.c.d → 12
    jne(0, 6),                 // 8: → 15
    load(CTX_USER_IP6 + 12),   // 9
    jeq(IP6_LAST_WORD_ONE, 6), // 10: ::1 → 17
    goto(3),                   // 11: → 15
    load(CTX_USER_IP6 + 12),   // 12
    and(0xff),                 // 13: primeiro octeto do IPv4 mapeado
    jeq(LOOPBACK_OCTET, 2),    // 14: → 17
    ret(0),                    // 15
    EXIT_INSN,                 // 16
    ret(1),                    // 17
    EXIT_INSN,                 // 18
];

/// Um `union bpf_attr`, montado campo a campo. 128 bytes cobrem todo comando
/// usado aqui; o resto fica zerado, que é o que o kernel exige.
struct Attr([u8; ATTR_SIZE]);

/// Tamanho informado ao kernel; o array tem exatamente isso.
const ATTR_SIZE_C: libc::c_uint = 128;
const ATTR_SIZE: usize = ATTR_SIZE_C as usize;

impl Attr {
    const fn new() -> Self {
        Self([0; ATTR_SIZE])
    }
    fn u32(&mut self, off: usize, v: u32) -> &mut Self {
        self.0[off..off + 4].copy_from_slice(&v.to_le_bytes());
        self
    }
    fn u64(&mut self, off: usize, v: u64) -> &mut Self {
        self.0[off..off + 8].copy_from_slice(&v.to_le_bytes());
        self
    }
    const fn read_u32(&self, off: usize) -> u32 {
        u32::from_le_bytes([
            self.0[off],
            self.0[off + 1],
            self.0[off + 2],
            self.0[off + 3],
        ])
    }
}

fn bpf(cmd: libc::c_long, attr: &mut Attr) -> std::io::Result<libc::c_long> {
    // SAFETY: `attr` é um buffer válido do tamanho informado, e o kernel só lê
    // e escreve dentro dele (e nos ponteiros que os campos apontam, todos para
    // memória viva durante a chamada).
    let r = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.0.as_mut_ptr(), ATTR_SIZE_C) };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn fd_from(r: libc::c_long) -> std::io::Result<OwnedFd> {
    let raw = i32::try_from(r).map_err(|_| std::io::Error::other("fd fora de faixa"))?;
    // SAFETY: o kernel acabou de devolver este descritor, e ninguém mais o tem.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Carrega um programa e devolve o descritor dele.
fn load_prog(insns: &[Insn], attach_type: u32, name: &str) -> std::io::Result<OwnedFd> {
    let code: Vec<u8> = insns.iter().flat_map(|i| i.bytes()).collect();
    let license = CString::new("GPL").map_err(std::io::Error::other)?;
    let mut log = vec![0u8; 4096];

    let mut attr = Attr::new();
    attr.u32(0, BPF_PROG_TYPE_CGROUP_SOCK_ADDR)
        .u32(
            4,
            u32::try_from(insns.len()).map_err(std::io::Error::other)?,
        )
        .u64(8, code.as_ptr() as u64)
        .u64(16, license.as_ptr() as u64)
        .u32(24, 1)
        .u32(28, u32::try_from(log.len()).map_err(std::io::Error::other)?)
        .u64(32, log.as_mut_ptr() as u64)
        .u32(68, attach_type);
    let n = name.len().min(15);
    attr.0[48..48 + n].copy_from_slice(&name.as_bytes()[..n]);

    bpf(BPF_PROG_LOAD, &mut attr)
        .and_then(fd_from)
        .map_err(|e| {
            // O verificador explica a recusa no log; sem ele o erro é só EINVAL.
            let msg = String::from_utf8_lossy(&log);
            let msg = msg.trim_end_matches('\0').trim();
            if msg.is_empty() {
                e
            } else {
                std::io::Error::new(e.kind(), format!("{e}: {msg}"))
            }
        })
}

fn open_cgroup(path: &Path) -> std::io::Result<OwnedFd> {
    std::fs::File::open(path).map(OwnedFd::from)
}

/// Prende os dois programas ao `selynt.slice`, substituindo os que houver.
///
/// Modo exclusivo, de propósito: prender de novo troca o programa em vez de
/// empilhar outro, e sem a flag de override nenhum cgroup filho consegue
/// trocá-lo pelo seu.
pub fn attach() -> std::io::Result<()> {
    attach_to(Path::new(SLICE_CGROUP))
}

/// Prende os programas a um cgroup qualquer — o do painel, ou um de teste.
pub fn attach_to(cgroup: &Path) -> std::io::Result<()> {
    let cg = open_cgroup(cgroup)?;
    for (prog, ty, name) in [
        (&PROG_V4[..], BPF_CGROUP_INET4_BIND, NAME_V4),
        (&PROG_V6[..], BPF_CGROUP_INET6_BIND, NAME_V6),
    ] {
        let fd = load_prog(prog, ty, name)?;
        let mut attr = Attr::new();
        attr.u32(
            0,
            u32::try_from(cg.as_raw_fd()).map_err(std::io::Error::other)?,
        )
        .u32(
            4,
            u32::try_from(fd.as_raw_fd()).map_err(std::io::Error::other)?,
        )
        .u32(8, ty);
        bpf(BPF_PROG_ATTACH, &mut attr)?;
        // A anexação mantém o programa vivo; o descritor pode fechar.
    }
    Ok(())
}

/// Solta os dois programas — só na remoção do plugin.
pub fn detach() -> std::io::Result<()> {
    let Ok(cg) = open_cgroup(Path::new(SLICE_CGROUP)) else {
        return Ok(());
    };
    for ty in [BPF_CGROUP_INET4_BIND, BPF_CGROUP_INET6_BIND] {
        let mut attr = Attr::new();
        attr.u32(
            0,
            u32::try_from(cg.as_raw_fd()).map_err(std::io::Error::other)?,
        )
        .u32(8, ty);
        match bpf(BPF_PROG_DETACH, &mut attr) {
            // Nada preso: já é o estado pedido.
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            other => {
                other?;
            }
        }
    }
    Ok(())
}

/// Nomes dos programas presos ao slice num gancho.
fn attached_names(cg: &OwnedFd, ty: u32) -> Vec<String> {
    let mut ids = [0u32; 8];
    let mut attr = Attr::new();
    attr.u32(0, u32::try_from(cg.as_raw_fd()).unwrap_or(0))
        .u32(4, ty)
        .u64(16, ids.as_mut_ptr() as u64)
        .u32(24, 8);
    if bpf(BPF_PROG_QUERY, &mut attr).is_err() {
        return Vec::new();
    }
    let count = (attr.read_u32(24) as usize).min(ids.len());

    ids[..count]
        .iter()
        .filter_map(|&id| {
            let mut a = Attr::new();
            a.u32(0, id);
            let fd = bpf(BPF_PROG_GET_FD_BY_ID, &mut a).and_then(fd_from).ok()?;
            // `struct bpf_prog_info`: o nome fica em 64..80.
            let mut info = [0u8; 256];
            let mut a = Attr::new();
            a.u32(0, u32::try_from(fd.as_raw_fd()).ok()?)
                .u32(4, 256)
                .u64(8, info.as_mut_ptr() as u64);
            bpf(BPF_OBJ_GET_INFO_BY_FD, &mut a).ok()?;
            let name = &info[64..80];
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            Some(String::from_utf8_lossy(&name[..end]).to_string())
        })
        .collect()
}

/// Se os dois programas do painel estão presos ao `selynt.slice`.
pub fn active() -> bool {
    active_on(Path::new(SLICE_CGROUP))
}

/// Se os dois programas do painel estão presos a um cgroup.
pub fn active_on(cgroup: &Path) -> bool {
    let Ok(cg) = open_cgroup(cgroup) else {
        return false;
    };
    attached_names(&cg, BPF_CGROUP_INET4_BIND)
        .iter()
        .any(|n| n == NAME_V4)
        && attached_names(&cg, BPF_CGROUP_INET6_BIND)
            .iter()
            .any(|n| n == NAME_V6)
}

/// Se o slice das aplicações existe — sem ele não há app a proteger.
pub fn slice_exists() -> bool {
    Path::new(SLICE_CGROUP).is_dir()
}

/// Garante a proteção antes de um processo de aplicação nascer.
///
/// O slice é implícito: o systemd o cria quando o primeiro app sobe e pode
/// descartá-lo quando o último para, levando o programa junto. Por isso isto
/// roda antes de cada spawn — cria o slice, prende o programa, e só então o
/// scope do app nasce, já com a regra herdada. Com `refresh`, prende de novo
/// mesmo que esteja ativo: é o que atualiza o programa depois de uma troca de
/// binário (`setup`, `boot-recover`).
pub fn ensure(refresh: bool) -> std::io::Result<()> {
    if !slice_exists() {
        let ok = std::process::Command::new("systemctl")
            .args(["start", SLICE_UNIT])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok || !slice_exists() {
            return Err(std::io::Error::other(format!(
                "could not create {SLICE_UNIT}"
            )));
        }
    }
    if refresh || !active() {
        attach()?;
    }
    Ok(())
}

#[cfg(test)]
// O interpretador reproduz a aritmética do BPF, que é de inteiros de largura
// fixa com sinal e truncamento por definição — os casts são a semântica.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::{Insn, PROG_V4, PROG_V6};

    /// Executa os bytes de um programa sobre um contexto `bpf_sock_addr`.
    ///
    /// Só o subconjunto usado aqui. Existe para que os testes verifiquem os
    /// programas que vão para o kernel, e não uma reescrita da regra em Rust.
    fn run(prog: &[Insn], ctx: &[u8; 72]) -> u64 {
        let mut r = [0u64; 11];
        let mut pc = 0usize;
        for _ in 0..1000 {
            let i = prog[pc];
            let dst = usize::from(i.regs & 0x0f);
            let src = usize::from(i.regs >> 4);
            let imm = i64::from(i.imm) as u64;
            let jump = |pc: usize| (pc as isize + 1 + isize::from(i.off)) as usize;
            pc = match i.code {
                0x61 => {
                    assert_eq!(src, 1, "só se lê do contexto");
                    let o = usize::try_from(i.off).unwrap();
                    r[dst] = u64::from(u32::from_le_bytes(ctx[o..o + 4].try_into().unwrap()));
                    pc + 1
                }
                0x16 if (r[dst] as u32) == (imm as u32) => jump(pc),
                0x56 if (r[dst] as u32) != (imm as u32) => jump(pc),
                0x16 | 0x56 => pc + 1,
                0x57 => {
                    r[dst] &= imm;
                    pc + 1
                }
                0xb7 => {
                    r[dst] = imm;
                    pc + 1
                }
                0x05 => jump(pc),
                0x95 => return r[0],
                c => panic!("opcode inesperado {c:#x}"),
            };
        }
        panic!("o programa não terminou");
    }

    fn ctx4(ip: [u8; 4], port: u16) -> [u8; 72] {
        let mut c = [0u8; 72];
        c[4..8].copy_from_slice(&ip);
        c[24..26].copy_from_slice(&port.to_be_bytes());
        c
    }

    fn ctx6(ip: [u8; 16], port: u16) -> [u8; 72] {
        let mut c = [0u8; 72];
        c[8..24].copy_from_slice(&ip);
        c[24..26].copy_from_slice(&port.to_be_bytes());
        c
    }

    fn v6(s: &str) -> [u8; 16] {
        s.parse::<std::net::Ipv6Addr>().unwrap().octets()
    }

    #[test]
    fn ipv4_follows_the_rule() {
        let casos = [
            ([127, 0, 0, 1], 3000, 1),   // loopback, porta fixa
            ([127, 9, 9, 9], 80, 1),     // todo o 127/8
            ([0, 0, 0, 0], 0, 1),        // o kernel escolhe a porta
            ([203, 0, 113, 7], 0, 1),    // idem, endereço específico
            ([0, 0, 0, 0], 3000, 0),     // serviço em todas as interfaces
            ([203, 0, 113, 7], 8080, 0), // serviço num IP público
            ([10, 0, 0, 1], 53, 0),      // rede privada também é de fora
        ];
        for (ip, port, esperado) in casos {
            assert_eq!(run(&PROG_V4, &ctx4(ip, port)), esperado, "{ip:?}:{port}");
        }
    }

    #[test]
    fn ipv6_follows_the_rule() {
        let casos = [
            ("::1", 3000, 1),
            ("::ffff:127.0.0.1", 3000, 1),
            ("::ffff:127.5.5.5", 22, 1),
            ("::", 0, 1), // musl antes de consultar o DNS
            ("2001:db8::1", 0, 1),
            ("::", 3000, 0),
            ("::ffff:0.0.0.0", 3000, 0),
            ("::ffff:203.0.113.7", 443, 0),
            ("2001:db8::1", 8080, 0),
            ("::2", 80, 0), // perto de ::1 não é ::1
            ("1::1", 80, 0),
            ("fe80::1", 80, 0),
        ];
        for (ip, port, esperado) in casos {
            assert_eq!(
                run(&PROG_V6, &ctx6(v6(ip), port)),
                esperado,
                "[{ip}]:{port}"
            );
        }
    }

    /// Todo salto cai dentro do programa e todo caminho termina em `exit` — o
    /// verificador do kernel recusaria o contrário, mas só no servidor.
    #[test]
    fn every_jump_lands_inside_the_program() {
        for prog in [&PROG_V4[..], &PROG_V6[..]] {
            for (pc, i) in prog.iter().enumerate() {
                if matches!(i.code, 0x16 | 0x56 | 0x05) {
                    let alvo = pc as isize + 1 + isize::from(i.off);
                    assert!((0..prog.len() as isize).contains(&alvo), "salto em {pc}");
                }
            }
            assert_eq!(prog.last().unwrap().code, 0x95);
        }
    }
}
