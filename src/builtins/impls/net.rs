// Copyright 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Builtins related to network operations and IP handling
//!
//! Note: spec says to return a hashset, but we're returning Vec for order
//! stability. where it is not inherently unique, we make guarantee that items
//! are unique as in a hash before converting to a vec. representation on the
//! result side in OPA is always an array (JSON)

use std::{collections::HashSet, net::IpAddr, str::FromStr};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde_json::Number;
use trust_dns_resolver::TokioAsyncResolver;

/// A unified address or CIDR block type
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy)]
enum Addr {
    CIDR(IpNet),
    IP(IpAddr),
}

/// builds a generic IP or CIDR container
fn addr_from_cidr_or_ip(s: &str) -> Result<Addr> {
    IpNet::from_str(s).map(Addr::CIDR).or_else(|_| {
        IpAddr::from_str(s)
            .map(Addr::IP)
            .context(format!("cannot parse {} into cidr or ip", s))
    })
}

/// this expand upon the go side handling additional cases where:
/// ip can contain ip (by way of strict equality)
/// cidr contains ip, but also ip is contained within cidr (flip the arguments)
/// * in the Go case, it's assumed thatmut  root call of `cidr_contains_matches`
///   LHS is CIDR and RHS is "CIDR or IP". here by being direction agnosic we
///   make no such assumption and handle a larger set of cases
#[allow(clippy::similar_names)]
fn addr_contains(left: &Addr, right: &Addr) -> bool {
    match (left, right) {
        (Addr::CIDR(cidr), Addr::IP(ip)) | (Addr::IP(ip), Addr::CIDR(cidr)) => cidr.contains(ip),
        (Addr::CIDR(lcidr), Addr::CIDR(rcidr)) => lcidr.contains(rcidr),
        (Addr::IP(lip), Addr::IP(rip)) => lip == rip,
    }
}

/// this is modeled after the Go side, where we want to get a term generically
/// from various IP/CIDR nestings:
/// "x":"y" -> "y"
/// "x":["y", "rest"] -> "y"
/// etc.
/// in this case, we work on the lowest level term: atom or array, and in the
/// case of array we always take the first atom.
fn get_addr_term(t: &serde_json::Value) -> Result<Addr> {
    if let Some(s) = t.as_str() {
        addr_from_cidr_or_ip(s)
    } else if let Some(v) = t.as_array() {
        let s = v
            .first()
            .context("value '' does not contain an address or cidr in first position")?
            .as_str()
            .context("value is not an address")?;
        addr_from_cidr_or_ip(s)
    } else {
        bail!("value '{:?}' does not contain an address or cidr", t)
    }
}

/// match one of the LHS items against a collection from the RHS
fn match_collection<I>(
    item: &Addr,
    item_key: &serde_json::Value,
    iter: I,
) -> Result<Vec<(serde_json::Value, serde_json::Value)>>
where
    I: Iterator<Item = Result<(serde_json::Value, Addr)>>,
{
    Ok(iter
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|(_, candidate)| addr_contains(item, candidate))
        .map(|(candidate_key, _)| (item_key.clone(), candidate_key))
        .collect::<Vec<_>>())
}

/// match one of the LHS items against an atom, collection, or hash
fn match_any(
    item: &Addr,
    item_key: &serde_json::Value,
    cidrs_or_ips: &serde_json::Value,
) -> Result<Vec<(serde_json::Value, serde_json::Value)>> {
    if let Some(rs) = cidrs_or_ips.as_str() {
        let ip_or_cidr = addr_from_cidr_or_ip(rs)?;
        if addr_contains(item, &ip_or_cidr) {
            Ok(vec![(item_key.clone(), cidrs_or_ips.clone())])
        } else {
            Ok(vec![])
        }
    } else if let Some(rv) = cidrs_or_ips.as_array() {
        match_collection(
            item,
            item_key,
            rv.iter().enumerate().map(|(idx, el)| {
                get_addr_term(el).map(|t| (serde_json::Value::Number(Number::from(idx)), t))
            }),
        )
    } else if let Some(robj) = cidrs_or_ips.as_object() {
        match_collection(
            item,
            item_key,
            robj.iter().map(|(k, el)| {
                get_addr_term(el).map(|t| (serde_json::Value::String(k.to_string()), t))
            }),
        )
    } else {
        bail!("cannot match against this data type")
    }
}

/// flatten `cidr_contains_matches` top level matching results
fn flatten_matches<I>(iter: I) -> Result<Vec<serde_json::Value>>
where
    I: Iterator<Item = Result<Vec<(serde_json::Value, serde_json::Value)>>>,
{
    Ok(iter
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .map(|(v1, v2)| serde_json::Value::Array(vec![v1, v2]))
        .collect::<Vec<_>>())
}

/// Checks if collections of cidrs or ips are contained within another
/// collection of cidrs and returns matches. This function is similar to
/// `net.cidr_contains` except it allows callers to pass collections of CIDRs or
/// IPs as arguments and returns the matches (as opposed to a boolean
/// result indicating a match between two CIDRs/IPs).
#[tracing::instrument(name = "net.cidr_contains_matches", err)]
pub fn cidr_contains_matches(
    cidrs: serde_json::Value,
    cidrs_or_ips: serde_json::Value,
) -> Result<serde_json::Value> {
    let res = if let Some(s) = cidrs.as_str() {
        match_any(
            &addr_from_cidr_or_ip(s)?,
            &serde_json::Value::String(s.to_string()),
            &cidrs_or_ips,
        )?
        .into_iter()
        .map(|(v1, v2)| serde_json::Value::Array(vec![v1, v2]))
        .collect::<Vec<_>>()
    } else if let Some(v) = cidrs.as_array() {
        flatten_matches(
            v.iter()
                .map(get_addr_term)
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .enumerate()
                .map(|(idx, item)| {
                    match_any(
                        &item,
                        &serde_json::Value::Number(Number::from(idx)),
                        &cidrs_or_ips,
                    )
                }),
        )?
    } else if let Some(obj) = cidrs.as_object() {
        flatten_matches(
            obj.iter()
                .map(|(k, el)| get_addr_term(el).map(|item| (k, item)))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .map(|(k, item)| {
                    match_any(
                        &item,
                        &serde_json::Value::String(k.to_string()),
                        &cidrs_or_ips,
                    )
                }),
        )?
    } else {
        bail!("cannot match against these arguments")
    };

    Ok(serde_json::Value::Array(res))
}

/// Expands CIDR to set of hosts  (e.g., `net.cidr_expand("192.168.0.0/30")`
/// generates 4 hosts: `{"192.168.0.0", "192.168.0.1", "192.168.0.2",
/// "192.168.0.3"}`).
#[tracing::instrument(name = "net.cidr_expand", err)]
pub fn cidr_expand(cidr: String) -> Result<Vec<String>> {
    // IpNet.hosts() is too smart because it excludes the
    // broadcast and network IP. which is why we're doing it manually here to
    // include all addresses in range including broadcast and network:
    let addrs = match IpNet::from_str(&cidr)? {
        IpNet::V4(net) => ipnet::Ipv4AddrRange::new(net.network(), net.broadcast())
            .map(|addr| addr.to_string())
            .collect::<HashSet<_>>(),
        IpNet::V6(net) => ipnet::Ipv6AddrRange::new(net.network(), net.broadcast())
            .map(|addr| addr.to_string())
            .collect::<HashSet<_>>(),
    };
    let mut res = addrs.into_iter().collect::<Vec<_>>();
    res.sort();

    Ok(res)
}

/// Merges IP addresses and subnets into the smallest possible list of CIDRs
/// (e.g., `net.cidr_merge(["192.0.128.0/24", "192.0.129.0/24"])` generates
/// `{"192.0.128.0/23"}`. This function merges adjacent subnets where possible,
/// those contained within others and also removes any duplicates.
///
/// Supports both IPv4 and IPv6 notations. IPv6 inputs need a prefix length
/// (e.g. "/128").
#[tracing::instrument(name = "net.cidr_merge", err)]
pub fn cidr_merge(addrs: serde_json::Value) -> Result<Vec<String>> {
    if let Some(addrs) = addrs.as_array() {
        let ipnets = addrs
            .iter()
            .map(|addr| {
                addr.as_str()
                    .and_then(|s| IpNet::from_str(s).ok())
                    .context("is not an address string")
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(IpNet::aggregate(&ipnets)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>())
    } else {
        bail!("data type not supported: {}", addrs);
    }
}

/// Returns the set of IP addresses (both v4 and v6) that the passed-in `name`
/// resolves to using the standard name resolution mechanisms available.
#[tracing::instrument(name = "net.lookup_ip_addr", err)]
pub async fn lookup_ip_addr(name: String) -> Result<Vec<String>> {
    let resolver = TokioAsyncResolver::tokio(
        trust_dns_resolver::config::ResolverConfig::default(),
        trust_dns_resolver::config::ResolverOpts::default(),
    )?;

    let response = resolver.lookup_ip(&name).await?;

    Ok(response
        .iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>())
}
