// Browser entry for the run timeline page. The control plane renders
// the timeline document into a JSON data island; this script parses
// it strictly and mounts the lanes. A malformed island prints the
// parse error as text — never a partial timeline.
import { parseTimeline, renderTimeline } from "./timeline";

const island = document.getElementById("timeline-data");
if (island === null) {
  throw new Error("timeline page shell is missing #timeline-data");
}
const host = document.getElementById("app");
if (host === null) {
  throw new Error("timeline page shell is missing #app");
}
try {
  const timeline = parseTimeline(JSON.parse(island.textContent ?? ""));
  host.innerHTML = renderTimeline(timeline);
} catch (error) {
  // Inert by construction: textContent cannot carry markup.
  host.textContent = error instanceof Error ? error.message : String(error);
}
