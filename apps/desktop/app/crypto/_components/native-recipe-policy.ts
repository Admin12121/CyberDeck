/** Native Recipes input gate. Locale-dependent Date.parse formats remain in JS. */
export function canUseNativeRecipe(
  input: string,
  steps: ReadonlyArray<{ opId: string; enabled: boolean }>,
  nativeOperations: ReadonlySet<string>,
): boolean {
  const enabled = steps.filter((step) => step.enabled);
  if (!enabled.every((step) => nativeOperations.has(step.opId))) return false;
  if (!enabled.some((step) => step.opId === "datetime_to_unix")) return true;

  // Multi-step pipelines may synthesize a date in any format. Stay with the
  // original TS semantics unless the single date input is unambiguously UTC
  // date-only or RFC3339 with a timezone and supported four-digit year.
  return enabled.length === 1 &&
    /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))?$/.test(input.trim());
}
