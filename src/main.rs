//use std::io;
// use domain::stub::StubResolver;

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
//use std::time::{Duration, Instant};
use std::time::{Instant};
use futures::executor::block_on;

use dns_lookup;
use domain::resolv::{StubResolver, stub::conf::{ResolvConf, ServerConf}};
use domain::base::question::Question;
use domain::base::name;
use domain::base::iana::rtype::Rtype;
use domain::base::ParsedName;
use domain::rdata::ZoneRecordData;

const DEBUG: bool = false;
const DEF_PATH: &str = "/run/NetworkManager/no-stub-resolv.conf";

struct StubNS {
    address: SocketAddr,
    name: String,
    stub: StubResolver,
    canonical: Option<String>,
    gai_name: Option<String>
}

fn resolve_one_synchronous(mut stub : &StubNS) {
    let name = &stub.name;
    let _r = match IpAddr::from_str(&name) {
        Ok(addr) => {
            match dns_lookup::lookup_addr(&addr) {
                Ok(host) => {
                    println!("{} has hostname {}", &name, &host);
                    //stub.gai_name = Some(name.clone());
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
    let _q = Question::new_in(name, Rtype::A);
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

    if DEBUG {
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
}

async fn forward(resolver: &StubResolver, name: name::UncertainName<Vec<u8>>) {
    let answer = match name {
        name::UncertainName::Absolute(ref name) => {
            resolver.lookup_host(name).await
        }
        name::UncertainName::Relative(ref name) => {
            resolver.search_host(name).await
        }
    };
    match answer {
        Ok(answer) => {
            if let name::UncertainName::Relative(_) = name {
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
    let start = Instant::now();
    match resolver.lookup_addr(addr).await {
        Ok(answer) => {
            let duration = Instant::now().duration_since(start);
            for name in answer.iter() {
                println!("{} has hostname {}", addr, name);
            }
            println!("Resolution of {0} took {1:.5}ms", addr, duration.as_micros());
        },
        Err(err) => println!("Query failed: {}", err),
    }
}

async fn get_root_soa(resolver: &StubResolver) {
    let root = name::Name::root_vec();
    let question = Question::new_in(root, Rtype::SOA);
    match resolver.query(question).await {
        Ok(answer) => {
            if answer.opt().is_some() {
                let opt = answer.opt().unwrap();
                if DEBUG {
                    println!(". SOA:");
                    println!("Response has OPT EDNS({}), UDP size: {}, DO: {}", opt.version(), opt.udp_payload_size(), opt.dnssec_ok());
                }
            }
            let mut seen_rrsig = false;
            let mut seen_soa = false;
            for r in answer.iter() {
                match r {
                    Ok((record, _section)) => {
                        if record.rtype() == Rtype::RRSIG {
                            seen_rrsig = true;
                        } else if record.rtype() == Rtype::SOA {
                            if DEBUG {
                                println!("SOA on name '{}'", record.owner());
                            }
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

async fn get_svcb(resolver: &StubResolver) {
    let dnsname: name::Name<Vec<u8>> = name::Name::from_str("_dns.resolver.arpa").unwrap();
    let question = Question::new_in(dnsname, Rtype::SVCB);
    match resolver.query(question).await {
        Ok(answer) => {
            match answer.answer() {
                Ok(records) => {
                    for rr in records {
                        // taken this crazy code from domain/examples/common/serve-utils.rs
                        let r = rr
                        .unwrap()
                        .into_record::<ZoneRecordData<_, ParsedName<_>>>()
                        .unwrap()
                        .unwrap();
                        //let r = rr.unwrap().to_record().unwrap();
                        println!("# _dns SVCB: {}", r);
                    }
                },
                Err(err2) => {
                    println!("SVCB parsing failed: {}", err2);
                }
            }
            if DEBUG {
                println!("# _dns SVCB:\n{}", answer.display_dig_style());
            }
        },
        Err(err) => {
            println!("SVCB query parsing error: {}", err);
        }
    };
}

async fn get_resinfo(resolver: &StubResolver) {
    let dnsname: name::Name<Vec<u8>> = name::Name::from_str("resolver.arpa").unwrap();
    // FIXME: RESINFO is not supported. query TXT
    let question = Question::new_in(dnsname, Rtype::TXT);
    match resolver.query(question).await {
        Ok(answer) => if DEBUG {
            println!("TXT:\n{}", answer.display_dig_style());
        },
        Err(err) => {
            println!("Root soa resolution failed: {}", err);
        }
    };
}

#[tokio::main]
async fn resolve_async(stubs: &Vec<StubNS>) {
    println!("Asynchronous resolution:");

    for stub in stubs {
        println!("# {}", stub.name);
        print_options(&stub.stub);
        let name = &stub.name;
        if let Ok(addr) = IpAddr::from_str(name) {
            reverse(&stub.stub, addr).await;
        } else if let Ok(name) = name::UncertainName::from_str(name) {
            forward(&stub.stub, name).await;
        } else {
            println!("Not a domain name: {}", name);
        }
        let f2 = get_root_soa(&stub.stub);
        let f3 = get_svcb(&stub.stub);
        //let f4 = get_resinfo(&stub.stub);
        futures::join!(f2, f3);
        println!();
    }
}

fn resolve_sync(names: &Vec<StubNS>) {
    println!("Blocking resolution:");
    for name in names {
        resolve_one_synchronous(&name);
    }
    println!();
}

fn get_nameservers(path: Option<String>) -> Vec<StubNS> {
    let mut servers = Vec::<StubNS>::new();
    let mut rc = ResolvConf::new();
    match path {
        Some(path) => {
            rc.parse_file(path).unwrap();
        },
        None => {
            //rc = ResolvConf::default();
            rc.parse_file(DEF_PATH).unwrap();
        }
    }
    for servconf in rc.servers {
        let srv = servconf.addr.ip().to_string();
        let mut found = false;
        for s in &servers {
            if &srv == &s.name {
                found = true;
            }
        }
        if !found {
            let mut oneserv = ResolvConf::new();
            oneserv.servers = vec![ServerConf::new(servconf.addr, servconf.transport)];
            oneserv.finalize();
            if DEBUG {
                println!("Details: {}", &oneserv);
            }
            let stub = StubResolver::from_conf(oneserv);
            println!("Server: {}", srv);
            servers.push(StubNS { address: servconf.addr, name: srv, stub: stub, canonical: None, gai_name: None });
        }
    }
    servers
}

fn main() {
    // example source: https://github.com/NLnetLabs/domain/blob/main/examples/lookup.rs
    //let mut names: Vec<_> = env::args().skip(1).collect();
    //if names.is_empty() {
    //
    let names: Vec<_> = env::args().skip(1).collect();
    let mut ns = Vec::<StubNS>::new();
    if names.is_empty() {
        ns = get_nameservers(None);
    } else {
        ns = get_nameservers(Some(names[0].clone()));
    }

    resolve_sync(&ns);
    resolve_async(&ns);
}
