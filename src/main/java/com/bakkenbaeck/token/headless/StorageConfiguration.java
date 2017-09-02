package com.bakkenbaeck.token.headless;

public class StorageConfiguration {

    private PostgresConfiguration postgres;
    private SqliteConfiguration sqlite;
    private String sslmode;

    public PostgresConfiguration getPostgres() {
        return postgres;
    }

    public String getSslmode() {
        return this.sslmode;
    }

    public void setSslmode(String sslmode) {
        this.sslmode = sslmode;
        if (this.postgres != null) {
            this.postgres.setSslmode(sslmode);
        }
    }

    public void setPostgres(PostgresConfiguration postgres) {
        this.postgres = postgres;
    }

    public SqliteConfiguration getSqlite() {
        return sqlite;
    }

    public void setSqlite(SqliteConfiguration sqlite) {
        this.sqlite = sqlite;
    }

    public void setEnvKey(String envKey) {
        String url = System.getenv(envKey);
        this.setUrl(url);
    }

    public void setUrl(String url) {
        if (url.startsWith("postgres://") || url.startsWith("postgresql://")) {
            this.postgres = new PostgresConfiguration();
            if (this.sslmode != null) {
                this.postgres.setSslmode(this.sslmode);
            }
            this.postgres.setUrl(url);
        } else if (url.startsWith("sqlite://")) {
            this.sqlite = new SqliteConfiguration();
            this.sqlite.setFile(url);
        }
    }

    public StorageConfiguration() { }
}
