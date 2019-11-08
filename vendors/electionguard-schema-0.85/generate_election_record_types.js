/**
 * Generates the typescript types of the electionguard json schemas
 */

const fs = require('fs');
const path = require('path');
const json_schema_to_typescript = require('json-schema-to-typescript');

const dir = fs.readdirSync(__dirname);
let json_schemas_path = path.join(__dirname, 'json_schemas.ts');
fs.writeFileSync(
    json_schemas_path, 
    "/* tslint:disable */\n" +
    "/**\n" +
    "* This file was automatically generated by generate_election_record_types.js.\n" +
    "* DO NOT MODIFY IT BY HAND. Instead, modify the source JSONSchema file,\n" +
    "* and run json-schema-to-typescript to regenerate this file.\n" +
    "*/\n\n" +
    "interface SchemaDict {\n" +
    "  [k: string]: any;\n" +
    "};\n\n" +
    "export const schemas: SchemaDict = {\n"
);

// Read the schemas and generate the type definitions. We will simultaneously
// generate a single javascript file with all the json schemas loaded as 
// javascript objects, json_schemas.ts.
for (const filename of dir) {
    const schema_path = path.join(__dirname, filename);
    const dirent = fs.statSync(schema_path);

    // it must be a file with ".schema.json" in the filename
    if (!dirent.isFile() || filename.indexOf(".schema.json") === -1) {
        continue;
    }

    // Once we know it is a schema, compile it
    const type_filename = filename.replace(".schema.json", ".d.ts");
    const type_path = path.join(__dirname, '@types', type_filename);
    const schema_str = fs.readFileSync(schema_path, 'utf8');
    const schema_json = JSON.parse(schema_str);

    json_schema_to_typescript.compile(schema_json)
        .then(ts => fs.writeFileSync(type_path, ts));

    // append to json_schemas.ts
    fs.writeFileSync(
        json_schemas_path, 
        " '" + filename + "': " + schema_str  + ",\n\n",
        {'flag': 'a+'}
    );
}


// end json_schemas.ts
fs.writeFileSync(
    json_schemas_path, 
    "};\n",
    {'flag': 'a+'}
);