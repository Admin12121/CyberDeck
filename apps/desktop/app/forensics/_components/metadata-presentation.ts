/** Display only native parser findings, with precise evidence-byte provenance. */
export interface ParsedMetadataField {
  namespace: string;
  key: string;
  value: string;
  offset: number;
}

export type MetadataGroup = "Camera" | "Capture times" | "Location" | "Other format fields";
export interface PresentedMetadataField extends ParsedMetadataField {
  label: string;
  group: MetadataGroup;
  suffix: string;
  offsetBasis: string;
}

const recognized: Record<string, { label: string; group: MetadataGroup; suffix?: string }> = {
  "exif.ifd0.make": { label: "Manufacturer", group: "Camera" },
  "exif.ifd0.model": { label: "Model", group: "Camera" },
  "exif.ifd0.orientation": { label: "Orientation code", group: "Camera" },
  "exif.ifd0.software": { label: "Software", group: "Camera" },
  "exif.ifd0.datetime": { label: "Modified time (timezone unspecified)", group: "Capture times" },
  "exif.subifd.datetime_original": { label: "Original capture (timezone unspecified without offset)", group: "Capture times" },
  "exif.subifd.datetime_digitized": { label: "Digitized (timezone unspecified without offset)", group: "Capture times" },
  "exif.subifd.utc_offset": { label: "Modified-time UTC offset (as recorded)", group: "Capture times" },
  "exif.subifd.utc_offset_original": { label: "Original capture UTC offset (as recorded)", group: "Capture times" },
  "exif.subifd.utc_offset_digitized": { label: "Digitized UTC offset (as recorded)", group: "Capture times" },
  "exif.subifd.subsecond": { label: "Modified-time fractional second digits", group: "Capture times" },
  "exif.subifd.subsecond_original": { label: "Original capture fractional second digits", group: "Capture times" },
  "exif.subifd.subsecond_digitized": { label: "Digitized fractional second digits", group: "Capture times" },
  "exif.subifd.iso": { label: "ISO", group: "Camera" },
  "exif.subifd.exposure_time": { label: "Exposure", group: "Camera" },
  "exif.subifd.focal_length_mm": { label: "Focal length", group: "Camera", suffix: " mm" },
  "exif.gps.latitude": { label: "Latitude", group: "Location", suffix: "°" },
  "exif.gps.longitude": { label: "Longitude", group: "Location", suffix: "°" },
  "exif.gps.altitude_meters": { label: "Altitude", group: "Location", suffix: " m" },
};

export const METADATA_GROUPS: readonly MetadataGroup[] = ["Camera", "Capture times", "Location", "Other format fields"];

export function presentMetadataFields(fields: readonly ParsedMetadataField[]): PresentedMetadataField[] {
  return fields.map((field) => {
    const name = recognized[`${field.namespace}.${field.key}`];
    return {
      ...field,
      label: name?.label ?? `${field.namespace}.${field.key}`,
      group: name?.group ?? "Other format fields",
      suffix: name?.suffix ?? "",
      offsetBasis: field.namespace === "exif.ifd0"
        ? "TIFF directory entry (legacy offset contract)"
        : "Evidence source value offset",
    };
  });
}

export function availableMetadataGroups(fields: readonly ParsedMetadataField[]) {
  const presented = presentMetadataFields(fields);
  return METADATA_GROUPS.map((name) => ({
    name,
    fields: presented.filter((field) => field.group === name),
  })).filter((group) => group.fields.length > 0);
}

export function sourceOffsetHex(offset: number): string {
  return Number.isSafeInteger(offset) && offset >= 0 ? `0x${offset.toString(16)}` : "unavailable";
}
