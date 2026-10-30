/**
 * Crypto feature controller layer.
 * Pure state transitions for the recipe builder. The view dispatches intents
 * here; IPC-backed actions (native hashing, engine jobs) join through lib/ipc.
 */
import { operationById, type RecipeState } from "../model";

export function addStep(state: RecipeState, opId: string): RecipeState {
  const op = operationById(opId);
  return {
    ...state,
    steps: [...state.steps, { opId, enabled: true, param: op?.paramDefault }],
  };
}

export function removeStep(state: RecipeState, index: number): RecipeState {
  return { ...state, steps: state.steps.filter((_, i) => i !== index) };
}

export function toggleStep(state: RecipeState, index: number): RecipeState {
  return {
    ...state,
    steps: state.steps.map((step, i) => (i === index ? { ...step, enabled: !step.enabled } : step)),
  };
}

export function setStepParam(state: RecipeState, index: number, param: string): RecipeState {
  return {
    ...state,
    steps: state.steps.map((step, i) => (i === index ? { ...step, param } : step)),
  };
}

export function moveStep(state: RecipeState, index: number, delta: -1 | 1): RecipeState {
  const target = index + delta;
  if (target < 0 || target >= state.steps.length) return state;
  const steps = state.steps.slice();
  const [step] = steps.splice(index, 1);
  steps.splice(target, 0, step);
  return { ...state, steps };
}

/** Move a step to an absolute drop position (drag-and-drop reorder). */
export function moveStepTo(state: RecipeState, from: number, to: number): RecipeState {
  const target = Math.max(0, Math.min(state.steps.length, to));
  if (target === from || target === from + 1) return state;
  const steps = state.steps.slice();
  const [step] = steps.splice(from, 1);
  steps.splice(from < target ? target - 1 : target, 0, step);
  return { ...state, steps };
}

export function setInput(state: RecipeState, input: string): RecipeState {
  return { ...state, input };
}

export function setAutoBake(state: RecipeState, autoBake: boolean): RecipeState {
  return { ...state, autoBake };
}

export function clearRecipe(state: RecipeState): RecipeState {
  return { ...state, steps: [] };
}

export function initialRecipeState(): RecipeState {
  return {
    steps: [
      { opId: "to_base64", enabled: true },
      { opId: "to_hex", enabled: false },
    ],
    input: "HackTool workbench: transformation pipeline seed input",
    autoBake: true,
  };
}
