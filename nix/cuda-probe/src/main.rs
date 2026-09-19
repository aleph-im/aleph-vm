mod cuda;

use actix_web::{App, HttpResponse, HttpServer, get, web};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

type Gpu = Arc<Mutex<cuda::Cuda>>;

fn failure(error: anyhow::Error) -> HttpResponse {
    HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("{error:#}") }))
}

#[get("/health")]
async fn health() -> HttpResponse {
    HttpResponse::Ok().body("ok")
}

#[get("/gpu")]
async fn gpu(card: web::Data<Gpu>) -> HttpResponse {
    let card = card.get_ref().clone();
    let n = 1u32 << 20;
    match web::block(move || {
        let g = card.lock().unwrap();
        g.saxpy(n).map(|ok| (g.device.clone(), ok))
    })
    .await
    {
        Ok(Ok((device, ok))) => HttpResponse::Ok()
            .json(serde_json::json!({ "device": device, "n": n, "kernel": "saxpy", "ok": ok })),
        Ok(Err(error)) => failure(error),
        Err(error) => failure(error.into()),
    }
}

#[derive(Deserialize)]
struct BandwidthQuery {
    mib: usize,
}

#[get("/bandwidth")]
async fn bandwidth(card: web::Data<Gpu>, query: web::Query<BandwidthQuery>) -> HttpResponse {
    let mib = query.mib;
    if !(1..=8192).contains(&mib) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "mib must be within 1..=8192" }));
    }
    let card = card.get_ref().clone();
    match web::block(move || card.lock().unwrap().bandwidth(mib)).await {
        Ok(Ok((up, down, ok))) => HttpResponse::Ok()
            .json(serde_json::json!({ "mib": mib, "h2d_mib_s": up, "d2h_mib_s": down, "ok": ok })),
        Ok(Err(error)) => failure(error),
        Err(error) => failure(error.into()),
    }
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    // Fail at start, not on the first request: a workload that cannot reach
    // the card exits and the guest init powers the VM off.
    let card: Gpu = Arc::new(Mutex::new(cuda::Cuda::open()?));
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(card.clone()))
            .service(health)
            .service(gpu)
            .service(bandwidth)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    Ok(())
}
