import { appendFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { Plugin } from "@opencode/plugin";

export default Plugin.define({
  id: "localci.review-usage",
  async setup(ctx) {
    const { journal, nonce, allowRateLimit } = ctx.options;
    if (typeof journal !== "string" || typeof nonce !== "string") {
      throw new Error("Local CI usage journal configuration missing");
    }
    const write = (data) => appendFileSync(journal, JSON.stringify({ nonce, ...data }) + "\n");
    const pending = new Map();
    const seen = new Set();
    // Post-run verdict nudges launch a new CLI process for the same session.
    // Its requests share the journal and must not reuse earlier identities.
    const instance = randomUUID();
    let sequence = 0;
    const controller = new AbortController();
    const listening = (async () => {
      try {
        for await (const event of ctx.event.subscribe({
          types: ["session.usage.updated"], signal: controller.signal,
        })) {
          if (seen.has(event.id)) continue;
          seen.add(event.id);
          const data = event.data;
          const queue = pending.get(data.sessionID) || [];
          const request = queue.shift();
          if (!request) {
            write({ kind: "error", reason: "Usage arrived without a metered request" });
            continue;
          }
          write({ kind: "usage", session: data.sessionID, request: request.id,
            request_kind: request.kind, tokens: data.tokens, cost: data.cost });
        }
      } catch {
        if (!controller.signal.aborted) write({ kind: "error", reason: "Usage event subscription failed" });
      }
    })();
    await ctx.session.hook("http.request", (event) => {
      const request = { id: `${instance}:${++sequence}`, kind: event.kind };
      const queue = pending.get(event.sessionID) || [];
      queue.push(request);
      pending.set(event.sessionID, queue);
      write({ kind: "request", session: event.sessionID, request: request.id, request_kind: event.kind });
    });
    await ctx.session.hook("http.response", (event) => {
      if (event.response.ok) return;
      if (allowRateLimit && event.response.status === 429) {
        const queue = pending.get(event.sessionID) || [];
        const request = queue[0];
        // A refusal can settle the only outstanding request for this session.
        // With concurrent requests, preserve the accounting failure.
        if (queue.length === 1) {
          queue.shift();
          write({ kind: "rejected", session: event.sessionID, request: request.id,
            request_kind: request.kind, status: 429 });
          return;
        }
      }
      write({ kind: "error", reason: "Provider request failed; complete usage unavailable" });
    });
    await ctx.session.hook("title", (event) => { event.result = "mergeCraft review"; });
    await ctx.session.hook("compaction", (event) => {
      event.system.push({ type: "text", text:
        "Preserve every unresolved review finding, its evidence and severity, verification state, unread ranges and required terminal-verdict work. Never convert an unresolved finding or incomplete coverage into approval. Source remains available for targeted rereads." });
    });
    write({ kind: "ready" });
    return async () => {
      controller.abort();
      await listening;
    };
  },
});
