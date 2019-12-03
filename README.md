# nVotes ElectionGuard SDK Verifier

## Building

This is a typescript project and uses the standard typescript toolchain. 
Install dependencies with:

```bash
npm install
```

Then you can build the project into javascript to the `build/` directory with:

```bash
npm run build
```

You can execute the unit tests with:

```bash
npm run test
```

You can generate package documentation with:

```bash
npm run doc 
```

## Running

You can run the verifier through the command line using `node`:

```bash
node build/src/bin/verifier.js $PATH_TO_ELECTION_RECORD.json
```

There are multiple election record examples in the directory `test/data` that
you can use with the verifier. For example, the following command should verify
correctly the `valid_encrypted.json` election record, which contains a valid
election record:

```bash
node build/src/bin/verifier.js tests/data/valid_encrypted.json
```

## Development

Note that we autogenerate both:
- The file `json_schemas.ts` (in directory `vendor/electionguard-schema-0.85`) 
  that contains the schemas as an object, so that they can be directly loaded 
  as a javascript dependency and not opening json files.
- The schema definitions in directory `vendor/electionguard-schema-0.85/@types`,
  so that the election record to be verified can be loaded from json in a typed
  manner.

When required, you can update the two generated json schemas derivatives 
mentioned above by running:

```bash
npm run generate_election_record_types
```

## Dependencies

The verifier uses minimal runtime dependencies to be very self-contained:
- [verificatum-vjsc]: Self-contained javascript cryptographic library for use 
  in electronic voting clients. Developed and maintained by Douglas Wikström 
  and part of the [Verificatum project]. It's directly included in the 
  `vendors` directory.
- [ajv]: A JSON Schema draft-07 validator, as the verifiable data is in JSON
  and the [ElectionGuard SDK Specification] includes the 
  [JSON Schema of the election record]. We have directly extracted and copied 
  verbatim these schemas in the `vendors` directory.
- [@types/node] The definitions for node.js, required to process command-line 
  arguments in the command-line verifier.

And these are the development-only extra dependencies:
- [jest]: typescript-friendy testing framework.
- [typedoc]: Generates package documentation.
- [json-schema-to-typescript]: Compile json schema to typescript typings.

## Contribute

There are multiple ways to contribute to the nVotes verifier:

- [Submit bugs] and help us verify fixes as they are checked in.
- Review [source code changes].

[nVotes]: https://nvotes.com

[ElectionGuard SDK]: https://github.com/microsoft/ElectionGuard-SDK

[ElectionGuard Preliminary Specification V0.85]: https://raw.githubusercontent.com/microsoft/ElectionGuard-SDK-Specification/master/Informal/ElectionGuardSpecificationV0.85.pdf

[ElectionGuard SDK Specification]: https://raw.githubusercontent.com/microsoft/ElectionGuard-SDK-Specification/master/Informal/ElectionGuardSpecificationV0.85.pdf

[jsonschema published in the formal specification]: https://github.com/microsoft/ElectionGuard-SDK-Specification/tree/781c38ec95416842d68a0adfceb5be63845497e8/Formal/schema/schemas

[verificatum-vjsc]: https://github.com/verificatum/verificatum-vjsc/

[Verificatum project]: https://verificatum.org

[ajv]: https://www.npmjs.com/package/ajv

[JSON Schema of the election record]: https://github.com/microsoft/ElectionGuard-SDK-Specification/tree/781c38ec95416842d68a0adfceb5be63845497e8/Formal/schema/schemas

[@types/node]: https://www.npmjs.com/package/@types/node

[jest]: https://jestjs.io/

[typedoc]: https://github.com/TypeStrong/typedoc

[Submit bugs]: https://github.com/nVotesOrg/nvotes-electionguard-sdk-verifier/issues

[source code changes]: https://github.com/nVotesOrg/juvenal-lib/pulls

[json-schema-to-typescript]: https://www.npmjs.com/package/json-schema-to-typescript
