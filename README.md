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