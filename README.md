# neospring

A toy [Spring '83 implementation](https://www.robinsloan.com/lab/specifying-spring-83/). See also [GitHub repo](https://github.com/robinsloan/spring-83) and the [current specification](https://github.com/robinsloan/spring-83/blob/main/draft-20220629.md#key-format).

The implementation is largely completely, but still need a persistent backend and shoring up operationally.

## Usage

    $ go build . && ./neospring

    $ curl http://localhost:3489/ab589f4dde9fce4180fcf42c7b05185b0a02a5d682e353fa39177995083e0583
    this is some test content and it should probably be expanded upon

## Development

Run the test suite:

    $ go test .

Run lint:

    $ golangci-lint --fix
