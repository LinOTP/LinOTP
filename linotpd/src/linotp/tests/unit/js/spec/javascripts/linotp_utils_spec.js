'use strict';

describe("isDefinedKey", function() {
  var simpleObject = {
    "a": "value a",
    "b with spaces": " ",
    "c": undefined,
    "d": { "a": false}
  }

  it("finds direct key", function() {
    var result = isDefinedKey(simpleObject, "a");

    expect(result).toBe(true);
  });

  it("finds direct key as array", function() {
    var result = isDefinedKey(simpleObject, ["a"]);

    expect(result).toBe(true);
  });

  it("finds key that leads to another object", function() {
    var result = isDefinedKey(simpleObject, ["d"]);

    expect(result).toBe(true);
  });

  it("does not find a key that is not defined", function() {
    var result_with_arraykey = isDefinedKey(simpleObject, ["e"]);
    var result_with_stringkey = isDefinedKey(simpleObject, "e");

    expect(result_with_arraykey).toBe(false);
    expect(result_with_stringkey).toBe(false);
  });

  it("finds nested key in an object", function() {
    var result = isDefinedKey(simpleObject, ["d", "a"]);

    expect(result).toBe(true);
  });

  it("does not find nested key that is not defined", function() {
    var result_outer = isDefinedKey(simpleObject, ["d"]);
    var result_inner = isDefinedKey(simpleObject, ["d", "b"]);

    expect(result_outer).toBe(true);
    expect(result_inner).toBe(false);
  });
});