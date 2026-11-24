use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use catalog_reads::product_tags::{read_product_tags, ProductTagsRequest};
use catalog_reads::{connect_read_only, router};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::Value;
use sqlx::any::install_default_drivers;
use sqlx::AnyPool;
use tower::ServiceExt;

const FIXTURE: &str = include_str!("../fixtures/product_tags.json");

const SCHEMA: &[&str] = &[
    r#"CREATE TABLE "Language" ("Id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "Name" TEXT NOT NULL, "LanguageCulture" TEXT NOT NULL, "Published" INTEGER NOT NULL)"#,
    r#"CREATE TABLE "Product" ("Id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "Name" TEXT NOT NULL, "SubjectToAcl" INTEGER NOT NULL, "LimitedToStores" INTEGER NOT NULL, "Published" INTEGER NOT NULL, "Deleted" INTEGER NOT NULL)"#,
    r#"CREATE TABLE "ProductTag" ("Id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "Name" TEXT NOT NULL)"#,
    r#"CREATE TABLE "Product_ProductTag_Mapping" ("Product_Id" INTEGER NOT NULL, "ProductTag_Id" INTEGER NOT NULL, PRIMARY KEY ("Product_Id", "ProductTag_Id"))"#,
    r#"CREATE TABLE "StoreMapping" ("Id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "EntityName" TEXT NOT NULL, "StoreId" INTEGER NOT NULL, "EntityId" INTEGER NOT NULL)"#,
    r#"CREATE TABLE "AclRecord" ("Id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "EntityName" TEXT NOT NULL, "CustomerRoleId" INTEGER NOT NULL, "EntityId" INTEGER NOT NULL)"#,
    r#"CREATE TABLE "LocalizedProperty" ("Id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "LocaleKeyGroup" TEXT NOT NULL, "LocaleKey" TEXT NOT NULL, "LocaleValue" TEXT NOT NULL, "LanguageId" INTEGER NOT NULL, "EntityId" INTEGER NOT NULL)"#,
    r#"CREATE TABLE "UrlRecord" ("Id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "EntityName" TEXT NOT NULL, "Slug" TEXT NOT NULL, "EntityId" INTEGER NOT NULL, "IsActive" INTEGER NOT NULL, "LanguageId" INTEGER NOT NULL)"#,
];

#[derive(Deserialize)]
struct Fixture {
    scenarios: Vec<Scenario>,
}

#[derive(Deserialize)]
struct Scenario {
    name: String,
    dataset: Dataset,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Dataset {
    languages: Vec<Language>,
    tags: Vec<Tag>,
    products: Vec<Product>,
}

#[derive(Deserialize)]
struct Language {
    id: i32,
    name: String,
    culture: String,
    published: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Tag {
    id: i32,
    name: String,
    se_name: String,
    localized: Vec<LocalizedTag>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalizedTag {
    language_id: i32,
    name: Option<String>,
    se_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Product {
    id: i32,
    published: bool,
    deleted: bool,
    limited_to_stores: bool,
    limited_to_store_ids: Vec<i32>,
    subject_to_acl: bool,
    acl_role_ids: Vec<i32>,
    tag_ids: Vec<i32>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    request: CaseRequest,
    expected: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CaseRequest {
    store_id: i32,
    role_ids: Vec<i32>,
    ignore_acl: bool,
    language_id: i32,
    culture: String,
    limit: i32,
}

impl CaseRequest {
    fn query_params(&self) -> Vec<(&'static str, String)> {
        let role_ids = self.role_ids.iter().map(i32::to_string).collect::<Vec<_>>().join(",");
        vec![
            ("storeId", self.store_id.to_string()),
            ("roleIds", role_ids),
            ("ignoreAcl", self.ignore_acl.to_string()),
            ("languageId", self.language_id.to_string()),
            ("culture", self.culture.clone()),
            ("limit", self.limit.to_string()),
        ]
    }

    fn query_string(&self) -> String {
        self.query_params()
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("&")
    }
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("fixture parses")
}

/// A SQLite file under the temp directory, removed on drop.
struct TempDatabase {
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "catalog-reads-test-{}-{}.sqlite",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_file(&path);
        Self { path }
    }

    fn url(&self) -> String {
        format!("sqlite://{}", self.path.display())
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

async fn seed(database: &TempDatabase, dataset: &Dataset) {
    install_default_drivers();
    let pool = AnyPool::connect(&format!("{}?mode=rwc", database.url())).await.expect("open writable seed connection");

    for statement in SCHEMA {
        sqlx::query(statement).execute(&pool).await.expect("create table");
    }

    for language in &dataset.languages {
        sqlx::query(r#"INSERT INTO "Language" ("Id", "Name", "LanguageCulture", "Published") VALUES ($1, $2, $3, $4)"#)
            .bind(language.id)
            .bind(&language.name)
            .bind(&language.culture)
            .bind(i32::from(language.published))
            .execute(&pool)
            .await
            .expect("insert language");
    }

    for tag in &dataset.tags {
        sqlx::query(r#"INSERT INTO "ProductTag" ("Id", "Name") VALUES ($1, $2)"#)
            .bind(tag.id)
            .bind(&tag.name)
            .execute(&pool)
            .await
            .expect("insert tag");
        insert_slug(&pool, tag.id, 0, &tag.se_name).await;

        for localized in &tag.localized {
            if let Some(name) = &localized.name {
                sqlx::query(
                    r#"INSERT INTO "LocalizedProperty" ("LocaleKeyGroup", "LocaleKey", "LocaleValue", "LanguageId", "EntityId")
                       VALUES ('ProductTag', 'Name', $1, $2, $3)"#,
                )
                .bind(name)
                .bind(localized.language_id)
                .bind(tag.id)
                .execute(&pool)
                .await
                .expect("insert localized name");
            }
            if let Some(se_name) = &localized.se_name {
                insert_slug(&pool, tag.id, localized.language_id, se_name).await;
            }
        }
    }

    for product in &dataset.products {
        sqlx::query(
            r#"INSERT INTO "Product" ("Id", "Name", "SubjectToAcl", "LimitedToStores", "Published", "Deleted")
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(product.id)
        .bind(format!("product {}", product.id))
        .bind(i32::from(product.subject_to_acl))
        .bind(i32::from(product.limited_to_stores))
        .bind(i32::from(product.published))
        .bind(i32::from(product.deleted))
        .execute(&pool)
        .await
        .expect("insert product");

        for store_id in &product.limited_to_store_ids {
            sqlx::query(r#"INSERT INTO "StoreMapping" ("EntityName", "StoreId", "EntityId") VALUES ('Product', $1, $2)"#)
                .bind(*store_id)
                .bind(product.id)
                .execute(&pool)
                .await
                .expect("insert store mapping");
        }
        for role_id in &product.acl_role_ids {
            sqlx::query(r#"INSERT INTO "AclRecord" ("EntityName", "CustomerRoleId", "EntityId") VALUES ('Product', $1, $2)"#)
                .bind(*role_id)
                .bind(product.id)
                .execute(&pool)
                .await
                .expect("insert ACL record");
        }
        for tag_id in &product.tag_ids {
            sqlx::query(r#"INSERT INTO "Product_ProductTag_Mapping" ("Product_Id", "ProductTag_Id") VALUES ($1, $2)"#)
                .bind(product.id)
                .bind(*tag_id)
                .execute(&pool)
                .await
                .expect("insert tag mapping");
        }
    }

    pool.close().await;
}

async fn insert_slug(pool: &AnyPool, tag_id: i32, language_id: i32, slug: &str) {
    sqlx::query(r#"INSERT INTO "UrlRecord" ("EntityName", "Slug", "EntityId", "IsActive", "LanguageId") VALUES ('ProductTag', $1, $2, 1, $3)"#)
        .bind(slug)
        .bind(tag_id)
        .bind(language_id)
        .execute(pool)
        .await
        .expect("insert slug");
}

async fn seeded_service(dataset: &Dataset) -> (TempDatabase, AnyPool) {
    let database = TempDatabase::new();
    seed(&database, dataset).await;
    let pool = connect_read_only(&database.url()).await.expect("open read-only pool");
    (database, pool)
}

async fn get(pool: &AnyPool, query: &str) -> (StatusCode, Vec<u8>) {
    let request = Request::get(format!("/api/catalog/product-tags?{query}")).body(Body::empty()).unwrap();
    let response = router(pool.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, body)
}

#[tokio::test]
async fn product_tags_fixture_cases_match_expected() {
    let fixture = fixture();
    let mut cases_run = 0;

    for scenario in &fixture.scenarios {
        let (_database, pool) = seeded_service(&scenario.dataset).await;

        for case in &scenario.cases {
            let params: HashMap<String, String> = case
                .request
                .query_params()
                .into_iter()
                .map(|(name, value)| (name.to_string(), value))
                .collect();
            let request = ProductTagsRequest::from_query(&params).expect("fixture request is valid");
            let items = read_product_tags(&pool, &request).await.expect("read succeeds");

            assert_eq!(
                serde_json::to_value(&items).unwrap(),
                case.expected,
                "scenario '{}', case '{}'",
                scenario.name,
                case.name
            );
            cases_run += 1;
        }
    }

    assert_eq!(cases_run, fixture.scenarios.iter().map(|s| s.cases.len()).sum::<usize>());
    assert!(cases_run > 0);
}

#[tokio::test]
async fn product_tags_http_route_returns_fixture_body() {
    let fixture = fixture();
    let scenario = &fixture.scenarios[0];
    let case = &scenario.cases[0];
    let (_database, pool) = seeded_service(&scenario.dataset).await;

    let (status, body) = get(&pool, &case.request.query_string()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), case.expected);
}

#[tokio::test]
async fn product_tags_http_rejects_missing_required_param() {
    let fixture = fixture();
    let (_database, pool) = seeded_service(&fixture.scenarios[0].dataset).await;

    for query in [
        "roleIds=3&languageId=1&culture=en-US",
        "storeId=1&roleIds=3&culture=en-US",
        "storeId=1&roleIds=3&languageId=1",
        "storeId=one&roleIds=3&languageId=1&culture=en-US",
        "storeId=1&roleIds=3,x&languageId=1&culture=en-US",
    ] {
        let (status, _) = get(&pool, query).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
    }
}

#[tokio::test]
async fn product_tags_http_rejects_empty_role_ids_without_ignore_acl() {
    let fixture = fixture();
    let (_database, pool) = seeded_service(&fixture.scenarios[0].dataset).await;

    for query in [
        "storeId=1&roleIds=&languageId=1&culture=en-US",
        "storeId=1&languageId=1&culture=en-US",
        "storeId=1&roleIds=&ignoreAcl=false&languageId=1&culture=en-US",
    ] {
        let (status, _) = get(&pool, query).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
    }

    let (status, _) = get(&pool, "storeId=1&roleIds=&ignoreAcl=true&languageId=1&culture=en-US").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn product_tags_service_connection_rejects_writes() {
    let fixture = fixture();
    let (_database, pool) = seeded_service(&fixture.scenarios[0].dataset).await;

    let write = sqlx::query(r#"INSERT INTO "ProductTag" ("Id", "Name") VALUES (999, 'written')"#)
        .execute(&pool)
        .await;

    assert!(write.is_err(), "a write through the service pool must fail");
    let count: i64 = sqlx::query_scalar(r#"SELECT COUNT(*) FROM "ProductTag" WHERE "Id" = 999"#)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
