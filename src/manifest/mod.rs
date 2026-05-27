use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub project: String,
    #[serde(rename = "kdf_salt")]
    pub kdf_salt_b64: String,
    #[serde(flatten)]
    pub envs: Envs,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Envs {
    #[serde(default)]
    pub dev: Vec<EnvMapping>,
    #[serde(default)]
    pub prod: Vec<EnvMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvMapping {
    pub source: String,
    #[serde(rename = "target")]
    pub target_dir: String,
}

impl Manifest {
    pub fn new(project: &str) -> Self {
        Self {
            version: 1,
            project: project.to_string(),
            kdf_salt_b64: base64::encode(rand::random::<[u8; 16]>()),
            envs: Envs::default(),
        }
    }

    pub fn add_mapping(&mut self, env_name: &'static str, source: &str, target_dir: &str) {
        self.envs.add(env_name, source, target_dir);
    }

    pub fn get_mappings(&self, env_name: &str) -> &[EnvMapping] {
        match env_name {
            "dev" => &self.envs.dev,
            "prod" => &self.envs.prod,
            _ => &[],
        }
    }

    pub fn remove_mapping(&mut self, env_name: &'static str, source: &str) {
        match env_name {
            "dev" => {
                self.envs.dev.retain(|m| m.source != source);
            }
            "prod" => {
                self.envs.prod.retain(|m| m.source != source);
            }
            _ => {}
        }
    }
}

impl Envs {
    pub fn add(&mut self, env_name: &'static str, source: &str, target_dir: &str) {
        let mappings = match env_name {
            "dev" => &mut self.dev,
            "prod" => &mut self.prod,
            _ => return,
        };

        // Check if source already exists
        if mappings.iter().any(|m| m.source == source) {
            eprintln!(
                "Warning: {} -> {} mapping already exists. Overwriting.",
                source, target_dir
            );
        }

        mappings.push(EnvMapping {
            source: source.to_string(),
            target_dir: target_dir.to_string(),
        });
    }
}

impl Default for Manifest {
    fn default() -> Self {
        Self::new("default")
    }
}
