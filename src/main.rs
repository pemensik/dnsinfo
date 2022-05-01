//use std::io;
// use domain::stub::StubResolver;

use std::env;
use std::net::IpAddr;
use std::str::FromStr;

use dns_lookup;
use domain::resolv::StubResolver;
use domain::base::question::Question;
use domain::base::name::UncertainDname;



fn resolve_one_synchronous(name : &String) {
    let _r = match IpAddr::from_str(&name) {
        Ok(addr) => {
            let host = dns_lookup::lookup_addr(&addr).unwrap();
            println!("{} has hostname {}", &name, &host);
        },
        Err(_err) => {
            for ip in dns_lookup::lookup_host(&name).unwrap() {
                println!("{} has address {}", &name, &ip);
            }
        },
    };
}

fn _async_test(_res : &StubResolver, name: &String) {
    let _q = Question::new_in(name, domain::base::iana::rtype::Rtype::A);
    // not like this
    //res.query(&q);
}

fn print_opt_bool(value: bool, desc: &str) {
    if value
        { print!("{} ", desc); }
    else
        { print!("no-{} ", desc); }
}

fn print_options(res : &StubResolver) {

    let o = res.options();

    println!();
    println!("Local stub options:");
    print_opt_bool(o.recurse, "recursion");
    print_opt_bool(o.use_vc, "TCP");
    print_opt_bool(o.use_edns0, "EDNS0");
    print_opt_bool(o.aa_only, "AA-only");
    println!();
    print!("attempts: {} ", o.attempts);
    print!("timeout: {} ", o.timeout.as_secs());
    println!("ndots: {}", o.ndots);
    println!();
}

async fn forward(resolver: &StubResolver, name: UncertainDname<Vec<u8>>) {
    let answer = match name {
        UncertainDname::Absolute(ref name) => {
            resolver.lookup_host(name).await
        }
        UncertainDname::Relative(ref name) => {
            resolver.search_host(name).await
        }
    };
    match answer {
        Ok(answer) => {
            if let UncertainDname::Relative(_) = name {
                println!("Found answer for {}", answer.qname());
            }
            let canon = answer.canonical_name();
            if canon != answer.qname() {
                println!("{} is an alias for {}", answer.qname(), canon);
            }
            for addr in answer.iter() {
                println!("{} has address {}", canon, addr);
            }
        }
        Err(err) => {
            println!("Query failed: {}", err);
        }
    }
}

async fn reverse(resolver: &StubResolver, addr: IpAddr) {
    match resolver.lookup_addr(addr).await {
        Ok(answer) => {
            for name in answer.iter() {
                println!("Host {} has domain name pointer {}", addr, name);
            }
        }
        Err(err) => println!("Query failed: {}", err),
    }
}

#[tokio::main]
async fn resolve_async(resolver: &StubResolver, names: &Vec<String>) {
    println!("Asynchronous resolution");
    for name in names {
        if let Ok(addr) = IpAddr::from_str(name) {
            reverse(&resolver, addr).await;
        } else if let Ok(name) = UncertainDname::from_str(name) {
            forward(&resolver, name).await;
        } else {
            println!("Not a domain name: {}", name);
        }
    }
}

fn resolve_sync(names: &Vec<String>) {
    println!("Blocking resolution:");
    for name in names {
        resolve_one_synchronous(&name);
    }
}

fn main() {
    // example source: https://github.com/NLnetLabs/domain/blob/main/examples/lookup.rs
    let names: Vec<_> = env::args().skip(1).collect();
    if names.is_empty() {
        println!("Usage: dnsinfo <hostname_or_addr> [...]");
        return;
    }

    resolve_sync(&names);

    let res = StubResolver::new();
    print_options(&res);
    resolve_async(&res, &names);
}
