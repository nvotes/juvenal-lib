import Ajv from 'ajv';

test('Testing ajv usage', () => {
  var schema = {
    "properties": {
      "foo": { "type": "string" },
      "bar": { "type": "number", "maximum": 3 }
    }
  };

  var ajv = new Ajv({allErrors: true});
  var validate = ajv.compile(schema);

  expect(validate({"foo": "abc", "bar": 2})).toBe(true);
  expect(validate({"foo": 2, "bar": 4})).toBe(false);
});
