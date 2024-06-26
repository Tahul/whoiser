import { defineBuildConfig } from 'unbuild'

export default defineBuildConfig({
  declaration: true,
  entries: ['src/index.ts'],
  rollup: {
    emitCJS: true,
  },
})
