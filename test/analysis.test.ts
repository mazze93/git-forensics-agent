import { describe, it, expect } from "vitest";
import {
  parseLsFilesStage,
  parseLsTree,
  parseMissingBlobHash,
  compareIndexToHead,
  detectIndexReplacement,
  correlateMissingBlobs,
  checkClaudeDrift,
  deriveFindings,
} from "../src/analysis";
import type { EvidenceSubmission } from "../src/types";

const h = (n: string) => n.repeat(40).slice(0, 40); // cheap 40-hex fixture

describe("parsers", () => {
  it("parses ls-files --stage including paths with spaces", () => {
    const out = `100644 ${h("a")} 0\tsrc/index.ts\n100644 ${h("b")} 0\tdocs/My File.md`;
    const rows = parseLsFilesStage(out);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ mode: "100644", hash: h("a"), stage: 0, path: "src/index.ts" });
    expect(rows[1]!.path).toBe("docs/My File.md");
  });

  it("tolerates a malformed / missing hash without throwing (corruption is the point)", () => {
    const out = `100644  0\tbroken.ts\n100644 ${h("c")} 0\tok.ts`;
    expect(() => parseLsFilesStage(out)).not.toThrow();
    const rows = parseLsFilesStage(out);
    expect(rows.some((r) => r.path === "ok.ts")).toBe(true);
  });

  it("parses ls-tree", () => {
    const out = `100644 blob ${h("a")}\tsrc/index.ts`;
    expect(parseLsTree(out)[0]).toMatchObject({ type: "blob", hash: h("a"), path: "src/index.ts" });
  });

  it("extracts the missing blob hash from a fatal status", () => {
    expect(parseMissingBlobHash("fatal: unable to read b6651396abcdef0123456789")).toBe(
      "b6651396abcdef0123456789",
    );
    expect(parseMissingBlobHash("nothing wrong here")).toBeNull();
  });
});

describe("compareIndexToHead", () => {
  it("flags additions/replacements and deletions on (hash,path) pairs", () => {
    const index = parseLsFilesStage(
      `100644 ${h("a")} 0\tkeep.ts\n100644 ${h("x")} 0\treplaced.ts\n100644 ${h("n")} 0\tnew.ts`,
    );
    const head = parseLsTree(
      `100644 blob ${h("a")}\tkeep.ts\n100644 blob ${h("o")}\treplaced.ts\n100644 blob ${h("d")}\tgone.ts`,
    );
    const diff = compareIndexToHead(index, head);
    const added = diff.addedOrReplaced.map((e) => e.path).sort();
    const deleted = diff.deleted.map((e) => e.path).sort();
    expect(added).toEqual(["new.ts", "replaced.ts"]); // replaced has a new hash
    expect(deleted).toEqual(["gone.ts", "replaced.ts"]); // old replaced hash no longer staged
  });
});

describe("detectIndexReplacement", () => {
  it("suspects wholesale replacement when staged paths are disjoint from HEAD", () => {
    const index = parseLsFilesStage(
      [1, 2, 3, 4, 5].map((i) => `100644 ${h(String(i))} 0\tother-project/file${i}.py`).join("\n"),
    );
    const head = parseLsTree(
      [1, 2, 3, 4, 5].map((i) => `100644 blob ${h("z" + i)}\treal/src${i}.ts`).join("\n"),
    );
    const v = detectIndexReplacement(index, head);
    expect(v.suspected).toBe(true);
    expect(v.overlapRatio).toBe(0);
  });

  it("does not cry wolf on a normal partial change", () => {
    const paths = ["a.ts", "b.ts", "c.ts", "d.ts", "e.ts"];
    const index = parseLsFilesStage(paths.map((p, i) => `100644 ${h(String(i))} 0\t${p}`).join("\n"));
    const head = parseLsTree(paths.map((p, i) => `100644 blob ${h(String(i))}\t${p}`).join("\n"));
    expect(detectIndexReplacement(index, head).suspected).toBe(false);
  });
});

describe("correlateMissingBlobs", () => {
  it("maps a shared missing hash to every repo it hit (coordinated activity)", () => {
    const shared = "b6651396" + "0".repeat(32);
    const map = correlateMissingBlobs([
      { repo: "praxis-aegis", missingBlobHash: shared },
      { repo: "context-synapse", missingBlobHash: shared },
      { repo: "secure-pride", missingBlobHash: shared },
      { repo: "unaffected", missingBlobHash: null },
    ]);
    expect(map[shared]).toEqual(["praxis-aegis", "context-synapse", "secure-pride"]);
  });
});

describe("checkClaudeDrift (semantic attack vector)", () => {
  it("is low risk when staged CLAUDE.md matches HEAD", () => {
    const v = checkClaudeDrift({ stagedHash: h("a"), headHash: h("a"), referenceHashes: [] });
    expect(v.matchesHead).toBe(true);
    expect(v.riskSummary).toMatch(/low risk/i);
  });

  it("is HIGH risk when staged CLAUDE.md matches a DIFFERENT repo's baseline", () => {
    const foreign = h("f");
    const v = checkClaudeDrift({
      stagedHash: foreign,
      headHash: h("a"),
      referenceHashes: [{ repo: "some-other-project", hash: foreign }],
    });
    expect(v.matchesHead).toBe(false);
    expect(v.matchesOtherRepo).toEqual([{ repo: "some-other-project", hash: foreign }]);
    expect(v.riskSummary).toMatch(/foreign governance|recontextualize/i);
  });

  it("is suspicious when staged CLAUDE.md matches nothing known", () => {
    const v = checkClaudeDrift({ stagedHash: h("9"), headHash: h("a"), referenceHashes: [] });
    expect(v.riskSummary).toMatch(/unrecognized|suspicious/i);
  });
});

describe("deriveFindings (end-to-end fold)", () => {
  const sub = (over: Partial<EvidenceSubmission>): EvidenceSubmission => ({
    repo: "r",
    capturedAt: 1,
    statusLine: "",
    missingBlobHash: null,
    index: [],
    head: [],
    fsckFlags: [],
    sealed: [],
    collectorId: "c",
    ...over,
  });

  it("escalates a cross-repo shared missing blob to critical", () => {
    const shared = "b6651396" + "0".repeat(32);
    const { findings, correlated } = deriveFindings([
      sub({ repo: "praxis-aegis", missingBlobHash: shared }),
      sub({ repo: "secure-pride", missingBlobHash: shared }),
    ]);
    expect(correlated[0]!.repos.length).toBe(2);
    const crit = findings.find((f) => f.kind === "cross-repo-correlation");
    expect(crit?.severity).toBe("critical");
  });

  it("surfaces a CLAUDE.md graft from a sibling repo as critical", () => {
    const foreign = h("f");
    const { findings } = deriveFindings([
      // victim repo: staged CLAUDE.md == foreign, head == its own
      sub({ repo: "secure-pride", claudeStagedHash: foreign, claudeHeadHash: h("a") }),
      // sibling whose HEAD CLAUDE.md IS the foreign hash -> the graft source
      sub({ repo: "some-other-project", claudeHeadHash: foreign }),
    ]);
    const drift = findings.find((f) => f.kind === "claude-semantic-drift");
    expect(drift?.severity).toBe("critical");
    expect(drift?.repo).toBe("secure-pride");
  });

  it("ranks critical findings first", () => {
    const shared = "b6651396" + "0".repeat(32);
    const { findings } = deriveFindings([
      sub({ repo: "a", missingBlobHash: shared, fsckFlags: ["error: badRefName .DS_Store"] }),
      sub({ repo: "b", missingBlobHash: shared }),
    ]);
    expect(findings[0]!.severity).toBe("critical");
  });
});
