use anyhow::Result;

/// `latch group list [--env <env>]`
pub async fn run_list(env: &str) -> Result<()> {
    anyhow::bail!(
        "Clone groups are temporarily disabled.\n\
         Use standalone files for now and run: 'latch commit --env {} && latch push --env {} --force'",
        env,
        env
    );
}

/// `latch group show <name> [--env <env>]`
pub async fn run_show(env: &str, _group_name: &str) -> Result<()> {
    anyhow::bail!(
        "Clone groups are temporarily disabled.\n\
         Use standalone files for now and run: 'latch commit --env {} && latch push --env {} --force'",
        env,
        env
    );
}
