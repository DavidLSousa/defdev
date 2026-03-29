#!/usr/bin/env node
import { program } from '../index.js';

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error((err as Error).message);
  process.exit(1);
});
