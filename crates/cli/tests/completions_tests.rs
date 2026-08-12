//! D7: clap-generated completions must produce output for all three
//! shells (run against the real binary).

#[test]
fn completions_generate_for_bash_zsh_fish() {
    for shell in ["bash", "zsh", "fish"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_latch"))
            .args(["completions", shell])
            .output()
            .unwrap();
        assert!(out.status.success(), "{shell} exited {:?}", out.status);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("latch"), "{shell} output names the binary");
        assert!(text.len() > 200, "{shell} output suspiciously short");
    }
}
