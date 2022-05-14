//use std::io;
// use domain::stub::StubResolver;

use std::env;
use std::net::IpAddr;
use std::str::FromStr;
//use std::time::{Duration, Instant};
use std::time::{Instant};

use dns_lookup;
use domain::resolv::StubResolver;
use domain::base::question::Question;
use domain::base::name;
use domain::base::iana::rtype::Rtype;


fn resolve_one_synchronous(name : &String) {
    let _r = match IpAddr::from_str(&name) {
        Ok(addr) => {
            match dns_lookup::lookup_addr(&addr) {
                Ok(host) => {
                    println!("{} has hostname {}", &name, &host);
                },
                Err(err) => {
                    println!("Error on {}: {}", name, err);
                }
            };
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

async fn forward(resolver: &StubResolver, name: name::UncertainDname<Vec<u8>>) {
    let answer = match name {
        name::UncertainDname::Absolute(ref name) => {
            resolver.lookup_host(name).await
        }
        name::UncertainDname::Relative(ref name) => {
            resolver.search_host(name).await
        }
    };
    match answer {
        Ok(answer) => {
            if let name::UncertainDname::Relative(_) = name {
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

async fn reverse(resolver: &StubResolver, addr: IpAddr, start: &Instant) {
    match resolver.lookup_addr(addr).await {
        Ok(answer) => {
            let duration = Instant::now().duration_since(*start);
            for name in answer.iter() {
                println!("Host {} has domain name pointer {}", addr, name);
            }
            println!("Resolution took {0:.5}ms", duration.as_secs_f32()/1000.0);
        },
        Err(err) => println!("Query failed: {}", err),
    }
}

async fn get_root_soa(resolver: &StubResolver) {
    let root = name::Dname::root_vec();
    let question = Question::new_in(root, Rtype::Soa);
    match resolver.query(question).await {
        Ok(answer) => {
            if answer.opt().is_some() {
                println!("Response has OPT section");
            }
            let mut seen_rrsig = false;
            let mut seen_soa = false;
            for r in answer.iter() {
                match r {
                    Ok((record, _section)) => {
                        if record.rtype() == Rtype::Rrsig {
                            seen_rrsig = true;
                        } else if record.rtype() == Rtype::Soa {
                            println!("SOA on name '{}'", record.owner());
                            seen_soa = true;
                        }

                    },
                    Err(err) => panic!("Failed parsing record: {}", err),
                }
            }
            println!("Seen RRSIG: {} SOA: {}", seen_rrsig, seen_soa);
        },
        Err(err) => {
            println!("Root soa resolution failed: {}", err);
        }
    };
}

#[tokio::main]
async fn resolve_async(resolver: &StubResolver, names: &Vec<String>) {
    println!("Asynchronous resolution");
    for name in names {
        if let Ok(addr) = IpAddr::from_str(name) {
            reverse(&resolver, addr, &Instant::now()).await;
        } else if let Ok(name) = name::UncertainDname::from_str(name) {
            forward(&resolver, name).await;
        } else {
            println!("Not a domain name: {}", name);
        }
    }
    get_root_soa(&resolver).await;
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
