# Contributing to EXENOM

Thank you for your interest in contributing to EXENOM! This guide will help you get started.

## 🚀 Getting Started

### Prerequisites

- [Bun](https://bun.sh) (or Node.js 18+)
- [Python 3.7+](https://python.org) (for the Python CLI)
- Git

### Setup

```bash
# Fork & clone the repo
git clone https://github.com/yourusername/exenom.git
cd exenom

# Install dependencies
bun install

# Start the scan engine (port 3004)
bun run easm-service

# In another terminal, start the web app (port 3000)
bun run dev
```

### Project Structure

```
exenom/
├── src/
│   ├── app/              # Next.js app (page.tsx = web terminal)
│   ├── lib/
│   │   └── easm/         # All 30 scanner modules
│   │       ├── types.ts       # Type definitions
│   │       ├── scanner.ts     # Orchestrator
│   │       ├── render.ts      # ANSI renderer (web terminal)
│   │       ├── payloads.ts    # 330+ WAF-bypass payloads
│   │       ├── apikeys.ts     # Multi-key API rotation
│   │       └── *.ts           # Individual modules
│   └── components/       # shadcn/ui components
├── cli/
│   └── easm.ts           # Real CLI (Bun/Node)
├── download/
│   └── easm.py           # Standalone Python CLI
├── mini-services/
│   └── easm-service/     # WebSocket scan engine
├── Dockerfile
├── docker-compose.yml
└── package.json
```

## 🧩 Adding a New Module

1. **Create the module file** in `src/lib/easm/`:
   ```typescript
   // src/lib/easm/mymodule.ts
   import type { MyResult } from "./types";

   export async function runMyModule(
     target: string,
     log: (msg: string) => void
   ): Promise<MyResult> {
     log("Running my module...");
     // ... your scanning logic
     return { findings: [] };
   }
   ```

2. **Add types** in `src/lib/easm/types.ts`:
   ```typescript
   export type ModuleId = ... | "mymodule";

   export interface MyResult {
     findings: { severity: "high" | "medium" | "low"; title: string; detail: string }[];
   }
   ```

3. **Wire into the scanner** in `src/lib/easm/scanner.ts`:
   - Import the module
   - Add to `ALL_MODULES`
   - Add to `ScanResults` interface
   - Add execution block
   - Add summary count

4. **Add a renderer** in `src/lib/easm/render.ts`:
   ```typescript
   function renderMyModule(r: MyResult): string { ... }
   // Add to renderResult() switch
   // Add to renderSummary() labels
   ```

5. **Add CLI renderer** in `cli/easm.ts` (same pattern as render.ts but with chalk/cli-table3)

6. **Export** in `src/lib/easm/index.ts`

7. **Test**: `bun run easm scan example.com --modules mymodule`

## 📝 Code Style

- TypeScript throughout with strict typing
- Use `import type` for type-only imports
- shadcn/ui components preferred over custom UI
- No emojis in code (only in README/docs)
- Test against `example.com` before submitting

## 🧪 Testing

```bash
# Lint
bun run lint

# Test a single module
bun run easm scan example.com --modules dns,http --no-subdomains

# Test Python CLI
python3 download/easm.py scan example.com --modules dns --no-subdomains
```

## 📬 Submitting Changes

1. Create a feature branch: `git checkout -b feature/my-new-module`
2. Commit: `git commit -m "Add mymodule — description"`
3. Push: `git push origin feature/my-new-module`
4. Open a Pull Request

## 📜 Code of Conduct

Be respectful, constructive, and welcoming. This is a security tool — always prioritize ethical use.

---

Built by **Rudresha RK** — Cybersecurity Undergraduate
