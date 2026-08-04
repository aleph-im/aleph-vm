use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use serde::Serialize;

#[derive(Serialize)]
struct FibResponse {
    n: u64,
    result: u64,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

fn fibonacci(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut a: u64 = 0;
    let mut b: u64 = 1;
    for _ in 1..n {
        let next = a.saturating_add(b);
        a = b;
        b = next;
    }
    b
}

#[get("/fib/{n}")]
async fn fib_handler(path: web::Path<u64>) -> impl Responder {
    let n = path.into_inner();
    let result = fibonacci(n);
    HttpResponse::Ok().json(FibResponse { n, result })
}

#[get("/health")]
async fn health_handler() -> impl Responder {
    HttpResponse::Ok().json(HealthResponse { status: "ok" })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(fib_handler).service(health_handler))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fib_base_cases() {
        assert_eq!(fibonacci(0), 0);
        assert_eq!(fibonacci(1), 1);
    }

    #[test]
    fn test_fib_known_values() {
        assert_eq!(fibonacci(10), 55);
        assert_eq!(fibonacci(20), 6765);
    }

    #[test]
    fn test_fib_large_saturates() {
        // fib(100) overflows u64, so it should saturate rather than panic
        let result = fibonacci(100);
        assert!(result > 0, "fib(100) should return a positive value");
    }
}
