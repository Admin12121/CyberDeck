import { test } from "node:test";
import assert from "node:assert/strict";
import { availableMetadataGroups, presentMetadataFields, sourceOffsetHex } from "./metadata-presentation.ts";

test("groups existing EXIF SubIFD camera, time and GPS without inventing missing fields", () => {
  const fields = [
    { namespace: "exif.ifd0", key: "make", value: "ACME", offset: 22 },
    { namespace: "exif.subifd", key: "datetime_original", value: "2024:02:29 13:47:59", offset: 92 },
    { namespace: "exif.subifd", key: "iso", value: "400", offset: 74 },
    { namespace: "exif.subifd", key: "exposure_time", value: "1/125 s", offset: 252 },
    { namespace: "exif.subifd", key: "focal_length_mm", value: "50.000", offset: 272 },
    { namespace: "exif.gps", key: "altitude_meters", value: "-123.500", offset: 76 },
  ];
  const groups = availableMetadataGroups(fields);
  assert.deepEqual(groups.map((group) => group.name), ["Camera", "Capture times", "Location"]);
  assert.equal(groups[0].fields.find((field) => field.key === "focal_length_mm").suffix, " mm");
  assert.equal(groups[1].fields[0].value, "2024:02:29 13:47:59");
  assert.match(groups[1].fields[0].label, /timezone unspecified/);
  assert.equal(groups[2].fields[0].value, "-123.500");
  assert.equal(groups[2].fields[0].suffix, " m");
  assert.match(groups[0].fields.find((field) => field.key === "make").offsetBasis, /directory entry/);
  assert.match(groups[0].fields.find((field) => field.key === "iso").offsetBasis, /source value/);
  assert.equal(sourceOffsetHex(groups[0].fields[0].offset), "0x16");
});
test("unknown optional tags remain visible, never fabricate values", () => {
  assert.deepEqual(availableMetadataGroups([]), []);
  assert.deepEqual(availableMetadataGroups([{ namespace: "png", key: "width", value: "3", offset: 16 }]).map((g) => g.name), ["Other format fields"]);
  assert.equal(presentMetadataFields([{ namespace: "exif.gps", key: "latitude", value: "27.012345", offset: 44 }])[0].suffix, "°");
  assert.equal(sourceOffsetHex(Number.NaN), "unavailable");
});

test("EXIF fractional and UTC-offset tags remain separately sourced and do not imply UTC conversion", () => {
  const fields = [
    { namespace: "exif.subifd", key: "datetime_original", value: "2024:02:29 13:47:59", offset: 92 },
    { namespace: "exif.subifd", key: "utc_offset_original", value: "+05:45", offset: 116 },
    { namespace: "exif.subifd", key: "subsecond_original", value: "00420", offset: 127 },
    { namespace: "exif.subifd", key: "utc_offset_digitized", value: "-05:00", offset: 248 },
  ];
  const groups = availableMetadataGroups(fields);
  assert.deepEqual(groups.map((group) => group.name), ["Capture times"]);
  const presented = groups[0].fields;
  assert.equal(presented[0].value, "2024:02:29 13:47:59");
  assert.match(presented[0].label, /timezone unspecified without offset/);
  assert.deepEqual(presented.slice(1).map((f) => f.value), ["+05:45", "00420", "-05:00"]);
  for (const item of presented) assert.equal(item.offsetBasis, "Evidence source value offset");
  assert.equal(sourceOffsetHex(presented[2].offset), "0x7f");
  assert.ok(!presented.some((f) => f.key === "datetime_digitized"));
});
