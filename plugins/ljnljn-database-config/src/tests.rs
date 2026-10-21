use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRun};

struct Root {
    path: PathBuf,
}

impl Root {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ljnljn-dbconfig-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, relative: &str, content: &str) -> PathBuf {
        let path = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    fn run_file(&self, path: &Path) -> TestRun {
        Harness::new(super::plugin)
            .run_with(
                "db_config_files",
                Fixture::files(&[path]),
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .expect("run")
    }

    fn run_system(&self) -> TestRun {
        Harness::new(super::plugin)
            .run_with(
                "db_config_system",
                Fixture::system("linux", &self.path),
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .expect("run")
    }

    fn run_evidence(&self) -> TestRun {
        Harness::new(super::plugin)
            .run_with(
                "db_config_evidence",
                Fixture::evidence(&[("part:1", &self.path)]),
                BTreeMap::new(),
                BTreeMap::new(),
            )
            .expect("run")
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn fixture() -> Root {
    let root = Root::new("all");
    root.write(
        "etc/mysql/my.cnf",
        "[client]\nuser = root\npassword = rootpass\n\n[mysqld]\nbind-address = 0.0.0.0\nport = 3306\n",
    );
    root.write(
        "etc/postgresql/16/main/postgresql.conf",
        "port = 5432\nlisten_addresses = 'localhost' # local only\n",
    );
    root.write(
        "etc/postgresql/16/main/pg_hba.conf",
        "local   all   all                 peer\nhost    all   all   0.0.0.0/0   md5\n",
    );
    root.write("root/.pgpass", "localhost:5432:app:alice:s3cret\n");
    root.write(
        "etc/redis/redis.conf",
        "bind 127.0.0.1\nrequirepass redispass\nuser default on >aclpass ~* +@all\n",
    );
    root.write(
        "etc/mongod.conf",
        "net:\n  port: 27017\n  bindIp: 127.0.0.1\nsecurity:\n  authorization: enabled\n",
    );
    root.write(
        "etc/elasticsearch/elasticsearch.yml",
        "http.port: 9200\nxpack.security.enabled: true\n",
    );
    root.write("var/opt/mssql/mssql.conf", "[sqlagent]\nenabled = true\n");
    root.write(
        "etc/oracle/listener.ora",
        "LISTENER = (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1521)))\n",
    );
    root
}

#[test]
fn selected_mysql_config_emits_settings_and_credential() {
    let root = Root::new("mysql");
    let path = root.write(
        "etc/mysql/my.cnf",
        "[client]\nuser = root\npassword = rootpass\n[mysqld]\nport = 3306\n",
    );
    let run = root.run_file(&path);

    assert_eq!(run.count("database.config.file"), 1);
    assert_eq!(run.count("database.config.setting"), 3);
    assert_eq!(run.count("database.config.credential"), 1);
    let file = run.of_type("database.config.file")[0];
    assert_eq!(file.text("product"), Some("mysql"));
    assert_eq!(file.text("format"), Some("ini"));
    assert_eq!(file.text("status"), Some("ok"));
    let credential = run.of_type("database.config.credential")[0];
    assert_eq!(credential.text("user"), Some("root"));
    assert_eq!(credential.text("value"), Some("rootpass"));
    let port = run
        .of_type("database.config.setting")
        .into_iter()
        .find(|setting| setting.text("key") == Some("port"))
        .expect("port");
    assert_eq!(port.text("section"), Some("mysqld"));
    assert_eq!(port.text("value"), Some("3306"));
}

#[test]
fn postgres_hba_and_pgpass_are_structured() {
    let root = fixture();
    let run = root.run_evidence();

    let hba = run.of_type("database.pg_hba.rule");
    assert_eq!(hba.len(), 2);
    let local = hba
        .iter()
        .find(|rule| rule.text("type") == Some("local"))
        .expect("local rule");
    assert_eq!(local.text("method"), Some("peer"));
    assert_eq!(local.text("address"), Some(""));
    let host = hba
        .iter()
        .find(|rule| rule.text("type") == Some("host"))
        .expect("host rule");
    assert_eq!(host.text("address"), Some("0.0.0.0/0"));
    assert_eq!(host.text("method"), Some("md5"));

    let pgpass = run
        .of_type("database.config.credential")
        .into_iter()
        .find(|credential| credential.text("user") == Some("alice"))
        .expect("pgpass credential");
    assert_eq!(pgpass.text("value"), Some("s3cret"));
    assert!(pgpass
        .text("context")
        .unwrap_or("")
        .contains("host=localhost"));
}

#[test]
fn redis_mongo_elasticsearch_mssql_and_oracle_are_recognized() {
    let root = fixture();
    let run = root.run_evidence();

    let products: Vec<&str> = run
        .of_type("database.config.file")
        .iter()
        .filter_map(|file| file.text("product"))
        .collect();
    for product in [
        "mysql",
        "postgresql",
        "redis",
        "mongodb",
        "elasticsearch",
        "mssql",
        "oracle",
    ] {
        assert!(products.contains(&product), "missing {product}");
    }

    let mongo_port = run
        .of_type("database.config.setting")
        .into_iter()
        .find(|setting| setting.text("product") == Some("mongodb") && setting.text("key") == Some("port"))
        .expect("mongo port");
    assert_eq!(mongo_port.text("section"), Some("net"));
    assert_eq!(mongo_port.text("value"), Some("27017"));

    let redis_acl = run
        .of_type("database.config.credential")
        .into_iter()
        .find(|credential| credential.text("kind") == Some("redis_acl_password"))
        .expect("redis acl credential");
    assert_eq!(redis_acl.text("user"), Some("default"));
    assert_eq!(redis_acl.text("value"), Some("aclpass"));

    assert!(run
        .of_type("database.config.setting")
        .iter()
        .any(|setting| setting.text("product") == Some("mssql") && setting.text("key") == Some("enabled")));
    assert!(run
        .of_type("database.config.setting")
        .iter()
        .any(|setting| setting.text("product") == Some("oracle") && setting.text("key") == Some("listener")));
}

#[test]
fn system_scope_finds_the_same_configs() {
    let root = fixture();
    let run = root.run_system();
    assert!(run.count("database.config.file") >= 8);
    assert!(run.count("database.pg_hba.rule") == 2);
    assert!(!run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "CONFIG_NOT_FOUND"));
}

#[test]
fn unknown_file_is_a_warning_not_empty_success() {
    let root = Root::new("unknown");
    let path = root.write("notes.txt", "this is not a database configuration\n");
    let run = root.run_file(&path);
    assert_eq!(run.count("database.config.file"), 1);
    assert_eq!(run.count("database.config.setting"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "UNSUPPORTED_CONFIG"));
    assert_eq!(run.of_type("database.config.file")[0].text("status"), Some("unsupported"));
}
