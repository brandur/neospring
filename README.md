# neospring [![Build Status](https://github.com/brandur/neospring/workflows/neospring%20CI/badge.svg)](https://github.com/brandur/neospring/actions)

A toy [Spring '83 implementation](https://www.robinsloan.com/lab/specifying-spring-83/). See also [GitHub repo](https://github.com/robinsloan/spring-83) and the [current specification](https://github.com/robinsloan/spring-83/blob/main/draft-20220629.md#key-format).

The implementation is largely complete, but still need a persistent backend and shoring up operationally.

I know there's other Go-based implementations, but this is a personal one just written for fun. Don't rely on it for long-term production use.

## Usage

    $ go build . && ./neospring

    $ curl http://localhost:3489/ab589f4dde9fce4180fcf42c7b05185b0a02a5d682e353fa39177995083e0583
    this is some test content and it should probably be expanded upon

Generate a new key:

    $ go build . && ./neospring keygen
    Brute forcing a Spring '83 key (this could take a while)
    Succeeded in 3m0.280434083s with 54276464 iterations
    Private key: 90ba51828ecc30132d4707d55d24456fbd726514cf56ab4668b62392798e2540
    Public  key: e90e9091b13a6e5194c1fed2728d1fdb6de7df362497d877b8c0b8f0883e1124

## Development

Run the test suite:

    $ go test .

Run lint:

    $ golangci-lint --fix
