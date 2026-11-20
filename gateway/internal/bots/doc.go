// Package bots is the gateway side of the MVP-22 bot catalogue (contracts
// v0.5, D35, contract/bots): the catalogue shipped in the binary, a
// request-path matcher and address verification with exactly the contract
// semantics, the optional FCrDNS cache and range fetch, and the robots.txt
// observation.
//
// Nothing here touches the network unless the operator switches it on
// (bots.verify.fcrdns, bots.ranges_fetch) or wires the robots.txt fetch
// (Robots, which only talks to the website's own upstream).
package bots
