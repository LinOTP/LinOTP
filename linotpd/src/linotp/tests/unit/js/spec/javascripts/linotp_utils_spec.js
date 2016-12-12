'use strict';

describe("isDefinedKey", function() {
  var simpleObject = {
    "a": "value a",
    "b with spaces": " ",
    "c": undefined,
    "d": { "a": false},
    "emil": { "a": false}
  }

  it("finds direct key", function() {
    expect(isDefinedKey(simpleObject, "a")).toBe(true);
    expect(isDefinedKey(simpleObject, "emil")).toBe(true);
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
    var result_with_arraykey = isDefinedKey(simpleObject, ["f"]);
    var result_with_stringkey = isDefinedKey(simpleObject, "f");

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

describe("parseMajorVersionNumber", function() {
  it("finds the major version", function() {
    expect(parseMajorVersionNumber("LinOTP 2.9.0")).toBe("2.9");
    expect(parseMajorVersionNumber("LinOTP 2.9.1")).toBe("2.9");
    expect(parseMajorVersionNumber("LinOTP 2.9.0.1")).toBe("2.9");
    expect(parseMajorVersionNumber("LinOTP 2.8.0.1")).toBe("2.8");
  });

  it("finds the major version for major only number", function() {
      expect(parseMajorVersionNumber("LinOTP 3.0")).toBe("3.0");
      expect(parseMajorVersionNumber("LinOTP 2.9")).toBe("2.9");
  })

  it("allows different text product names", function() {
      expect(parseMajorVersionNumber("LinOTP Test 3.0.1")).toBe("3.0");
      expect(parseMajorVersionNumber("LinOTP_Util 2.9")).toBe("2.9");
  })

  it("cuts off dev release identifiers", function() {
      expect(parseMajorVersionNumber("LinOTP 2.9.1.dev0")).toBe("2.9");
      expect(parseMajorVersionNumber("LinOTP 3.0.dev1")).toBe("3.0");
  })

  it("parses version numbers itself", function() {
      expect(parseMajorVersionNumber("2.9.1.dev0")).toBe("2.9");
      expect(parseMajorVersionNumber("2.9.dev0")).toBe("2.9");
      expect(parseMajorVersionNumber("2.9")).toBe("2.9");
      expect(parseMajorVersionNumber("2")).toBe("2.0");
  })
});

describe("parseMinorVersionNumber", function() {
  it("finds the minor version", function() {
    expect(parseMinorVersionNumber("LinOTP 2.9.0")).toBe("2.9.0");
    expect(parseMinorVersionNumber("LinOTP 2.9.1")).toBe("2.9.1");
    expect(parseMinorVersionNumber("LinOTP 2.9.0.1")).toBe("2.9.0");
    expect(parseMinorVersionNumber("LinOTP 2.8.0.1")).toBe("2.8.0");
  });

  it("finds the minor version for major only number", function() {
      expect(parseMinorVersionNumber("LinOTP 3.0")).toBe("3.0.0");
      expect(parseMinorVersionNumber("LinOTP 2.9")).toBe("2.9.0");
  })

  it("allows different text product names", function() {
      expect(parseMinorVersionNumber("LinOTP Test 3.0.1")).toBe("3.0.1");
      expect(parseMinorVersionNumber("LinOTP_Util 2.9")).toBe("2.9.0");
  })

  it("cuts off dev release identifiers", function() {
      expect(parseMinorVersionNumber("LinOTP 2.9.1.dev0")).toBe("2.9.1");
      expect(parseMinorVersionNumber("LinOTP 3.0.dev1")).toBe("3.0.0");
  })

  it("parses version numbers itself", function() {
      expect(parseMinorVersionNumber("2.9.1.dev0")).toBe("2.9.1");
      expect(parseMinorVersionNumber("2.9.dev0")).toBe("2.9.0");
      expect(parseMinorVersionNumber("2.9")).toBe("2.9.0");
      expect(parseMinorVersionNumber("2")).toBe("2.0.0");
  })
});

describe("compareVersionNumbers", function() {
  it("compares versions with same length", function() {
    expect(compareVersionNumbers("3.0.0", "3.0.0")).toBe(0);
    expect(compareVersionNumbers("3.0.1", "3.0.0")).toBe(1);
    expect(compareVersionNumbers("3.0.1", "3.0.0")).toBe(1);
    expect(compareVersionNumbers("2", "3")).toBe(-1);
    expect(compareVersionNumbers("2.9.0", "2.0.0")).toBe(1);
  });

  it("compares versions with different length", function() {
    expect(compareVersionNumbers("3.0.0", "3.0")).toBe(0);
    expect(compareVersionNumbers("3.0", "3.0.1")).toBe(-1);
    expect(compareVersionNumbers("2.1", "3")).toBe(-1);
    expect(compareVersionNumbers("2.1.1", "2.1")).toBe(1);
  });

});