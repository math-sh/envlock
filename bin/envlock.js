#!/usr/bin/env node
import { main } from '../src/cli.js';

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    process.stderr.write(`erro inesperado: ${error?.stack ?? error}\n`);
    process.exitCode = 1;
  });
