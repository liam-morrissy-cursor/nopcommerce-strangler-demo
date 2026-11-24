use std::collections::HashMap;
use std::error::Error;

use icu_collator::{Collator, CollatorOptions};
use icu_locid::Locale;
use serde::Serialize;
use sqlx::{AnyPool, FromRow};

/// A product tag with its localized name, slug and the number of visible products.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductTagItem {
    pub id: i64,
    pub name: String,
    pub se_name: String,
    pub product_count: i64,
}

/// `Roles` is never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acl {
    Ignore,
    Roles(Vec<i32>),
}

#[derive(Debug, Clone)]
pub struct ProductTagsRequest {
    /// `0` means no store restriction.
    pub store_id: i32,
    pub acl: Acl,
    pub language_id: i32,
    pub culture: Locale,
    pub limit: Option<usize>,
}

impl ProductTagsRequest {
    /// Fails closed: a missing or malformed required parameter, or no role ids without
    /// `ignoreAcl=true`, is an error rather than "no filter".
    pub fn from_query(params: &HashMap<String, String>) -> Result<Self, String> {
        let store_id = non_negative(params, "storeId")?;
        let language_id = non_negative(params, "languageId")?;

        let ignore_acl = match params.get("ignoreAcl").map(String::as_str) {
            None | Some("false") => false,
            Some("true") => true,
            Some(other) => return Err(format!("ignoreAcl must be true or false, got '{other}'")),
        };
        let role_ids = match params.get("roleIds").map(String::as_str) {
            None | Some("") => Vec::new(),
            Some(csv) => csv
                .split(',')
                .map(|id| id.parse::<i32>().map_err(|_| format!("roleIds must be a comma-separated list of integers, got '{csv}'")))
                .collect::<Result<Vec<_>, _>>()?,
        };
        let acl = match (ignore_acl, role_ids.is_empty()) {
            (true, _) => Acl::Ignore,
            (false, true) => return Err("roleIds is required unless ignoreAcl=true".to_string()),
            (false, false) => Acl::Roles(role_ids),
        };

        let culture = match params.get("culture").map(String::as_str) {
            None => return Err("culture is required (pass an empty value for the invariant culture)".to_string()),
            Some("") => Locale::UND,
            Some(name) => name.parse().map_err(|_| format!("culture '{name}' is not a valid locale"))?,
        };

        let limit = match params.get("limit") {
            None => None,
            Some(value) => {
                let limit: i32 = value.parse().map_err(|_| format!("limit must be an integer, got '{value}'"))?;
                usize::try_from(limit).ok().filter(|&limit| limit > 0)
            }
        };

        Ok(Self { store_id, acl, language_id, culture, limit })
    }
}

fn non_negative(params: &HashMap<String, String>, name: &str) -> Result<i32, String> {
    let value = params.get(name).ok_or_else(|| format!("{name} is required"))?;
    value
        .parse::<i32>()
        .ok()
        .filter(|&id| id >= 0)
        .ok_or_else(|| format!("{name} must be a non-negative integer, got '{value}'"))
}

#[derive(FromRow)]
struct TagCountRow {
    id: i64,
    name: String,
    product_count: i64,
    localized_name: Option<String>,
    localized_slug: Option<String>,
    default_slug: Option<String>,
}

/// Mirrors `CatalogModelFactory.PreparePopularProductTagsModelAsync`. Both sides break count ties
/// by lower tag id so that `limit` keeps the same tags.
pub async fn read_product_tags(pool: &AnyPool, request: &ProductTagsRequest) -> Result<Vec<ProductTagItem>, Box<dyn Error + Send + Sync>> {
    let published_languages: i64 = sqlx::query_scalar(r#"SELECT COUNT(*) FROM "Language" WHERE "Published""#)
        .fetch_one(pool)
        .await?;
    // nopCommerce reads localized names and slugs only when two or more languages are published.
    let localize = request.language_id > 0 && published_languages >= 2;

    let (sql, binds) = counts_query(request);
    let mut query = sqlx::query_as::<_, TagCountRow>(&sql);
    for bind in binds {
        query = query.bind(bind);
    }
    let mut rows = query.fetch_all(pool).await?;

    if let Some(limit) = request.limit {
        rows.truncate(limit);
    }

    let mut items: Vec<ProductTagItem> = rows
        .into_iter()
        .map(|row| {
            let localized = |value: Option<String>| value.filter(|value| localize && !value.is_empty());
            ProductTagItem {
                id: row.id,
                name: localized(row.localized_name).unwrap_or(row.name),
                se_name: localized(row.localized_slug).or(row.default_slug).unwrap_or_default(),
                product_count: row.product_count,
            }
        })
        .collect();

    let collator = Collator::try_new(&(&request.culture).into(), CollatorOptions::new())
        .map_err(|error| format!("no collation for culture '{}': {error}", request.culture))?;
    items.sort_by(|a, b| collator.compare(&a.name, &b.name));

    Ok(items)
}

/// One query text for PostgreSQL and SQLite, with its bind values in placeholder order.
fn counts_query(request: &ProductTagsRequest) -> (String, Vec<i32>) {
    let mut sql = String::from(
        r#"SELECT CAST(pt."Id" AS BIGINT) AS id,
       CAST(pt."Name" AS TEXT) AS name,
       COUNT(*) AS product_count,
       (SELECT CAST(lp."LocaleValue" AS TEXT) FROM "LocalizedProperty" lp
         WHERE lp."LocaleKeyGroup" = 'ProductTag' AND lp."LocaleKey" = 'Name'
           AND lp."LanguageId" = $1 AND lp."EntityId" = pt."Id"
         ORDER BY lp."Id" LIMIT 1) AS localized_name,
       (SELECT CAST(ur."Slug" AS TEXT) FROM "UrlRecord" ur
         WHERE ur."EntityName" = 'ProductTag' AND ur."IsActive"
           AND ur."LanguageId" = $1 AND ur."EntityId" = pt."Id"
         ORDER BY ur."Id" DESC LIMIT 1) AS localized_slug,
       (SELECT CAST(ur."Slug" AS TEXT) FROM "UrlRecord" ur
         WHERE ur."EntityName" = 'ProductTag' AND ur."IsActive"
           AND ur."LanguageId" = 0 AND ur."EntityId" = pt."Id"
         ORDER BY ur."Id" DESC LIMIT 1) AS default_slug
FROM "ProductTag" pt
JOIN "Product_ProductTag_Mapping" ptm ON ptm."ProductTag_Id" = pt."Id"
JOIN "Product" p ON p."Id" = ptm."Product_Id"
WHERE NOT p."Deleted" AND p."Published""#,
    );
    let mut binds = vec![request.language_id];

    // Like `StoreMappingService.ApplyStoreMapping` and `AclService.ApplyAcl`, each filter is
    // skipped while no product has a row in its mapping table.
    if request.store_id > 0 {
        binds.push(request.store_id);
        let store = binds.len();
        sql.push_str(&format!(
            r#"
  AND (NOT EXISTS (SELECT 1 FROM "StoreMapping" WHERE "EntityName" = 'Product')
       OR NOT p."LimitedToStores"
       OR EXISTS (SELECT 1 FROM "StoreMapping" sm
                   WHERE sm."EntityName" = 'Product' AND sm."EntityId" = p."Id" AND sm."StoreId" = ${store}))"#
        ));
    }

    if let Acl::Roles(role_ids) = &request.acl {
        let placeholders = role_ids
            .iter()
            .map(|role_id| {
                binds.push(*role_id);
                format!("${}", binds.len())
            })
            .collect::<Vec<_>>()
            .join(", ");
        sql.push_str(&format!(
            r#"
  AND (NOT EXISTS (SELECT 1 FROM "AclRecord" WHERE "EntityName" = 'Product')
       OR NOT p."SubjectToAcl"
       OR EXISTS (SELECT 1 FROM "AclRecord" acl
                   WHERE acl."EntityName" = 'Product' AND acl."EntityId" = p."Id" AND acl."CustomerRoleId" IN ({placeholders})))"#
        ));
    }

    sql.push_str(
        r#"
GROUP BY pt."Id", pt."Name"
ORDER BY product_count DESC, id ASC"#,
    );
    (sql, binds)
}
