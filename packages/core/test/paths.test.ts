import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  CHECKPOINT_PATH,
  archivedCheckpointPath,
  decodeTileIndex,
  encodeTileIndex,
  entryBundlePath,
  parseLogPath,
  tilePath,
} from '../src/paths.ts';

describe('tile index encoding', () => {
  it.each([
    [0, '000'],
    [7, '007'],
    [999, '999'],
    [1000, 'x001/000'],
    [1234067, 'x001/x234/067'],
    [1_000_000, 'x001/x000/000'],
  ])('%i -> %s', (n, s) => {
    expect(encodeTileIndex(n)).toBe(s);
    expect(decodeTileIndex(s)).toBe(n);
  });

  it('round-trips any safe index', () => {
    fc.assert(
      fc.property(fc.maxSafeNat(), (n) => {
        expect(decodeTileIndex(encodeTileIndex(n))).toBe(n);
      }),
    );
  });

  it.each([
    '',
    '1',
    '0000',
    'x000/001', // non-canonical leading zero element
    'x001',
    '001/000', // missing x prefix
    'x001/x000', // last element must not have x
    'x1/000',
    'x001//000',
    '-01',
    '1e2',
  ])('rejects non-canonical index %j', (s) => {
    expect(() => decodeTileIndex(s)).toThrow();
  });

  it('rejects negative and unsafe indexes', () => {
    expect(() => encodeTileIndex(-1)).toThrow();
    expect(() => encodeTileIndex(1.5)).toThrow();
    expect(() => encodeTileIndex(2 ** 53)).toThrow();
  });
});

describe('resource paths', () => {
  it('full and partial tiles', () => {
    expect(tilePath(0, 1234067, 256)).toBe('tile/0/x001/x234/067');
    expect(tilePath(2, 0, 1)).toBe('tile/2/000.p/1');
    expect(tilePath(1, 1, 17)).toBe('tile/1/001.p/17');
    expect(tilePath(63, 5, 255)).toBe('tile/63/005.p/255');
  });

  it('entry bundles', () => {
    expect(entryBundlePath(273, 112)).toBe('tile/entries/273.p/112');
    expect(entryBundlePath(1000, 256)).toBe('tile/entries/x001/000');
  });

  it('checkpoints', () => {
    expect(CHECKPOINT_PATH).toBe('checkpoint');
    expect(archivedCheckpointPath(70_000)).toBe('x-checkpoints/70000');
  });

  it('rejects invalid coordinates', () => {
    expect(() => tilePath(64, 0, 256)).toThrow();
    expect(() => tilePath(-1, 0, 256)).toThrow();
    expect(() => tilePath(0, 0, 0)).toThrow();
    expect(() => tilePath(0, 0, 257)).toThrow();
    expect(() => entryBundlePath(0, 0)).toThrow();
    expect(() => archivedCheckpointPath(-1)).toThrow();
  });
});

describe('parseLogPath', () => {
  it('parses every resource kind', () => {
    expect(parseLogPath('checkpoint')).toEqual({ kind: 'checkpoint' });
    expect(parseLogPath('tile/0/x001/x234/067')).toEqual({
      kind: 'tile',
      level: 0,
      index: 1234067,
      width: 256,
    });
    expect(parseLogPath('tile/1/001.p/17')).toEqual({
      kind: 'tile',
      level: 1,
      index: 1,
      width: 17,
    });
    expect(parseLogPath('tile/entries/273.p/112')).toEqual({
      kind: 'bundle',
      index: 273,
      width: 112,
    });
    expect(parseLogPath('tile/entries/000')).toEqual({ kind: 'bundle', index: 0, width: 256 });
    expect(parseLogPath('x-checkpoints/70000')).toEqual({
      kind: 'archived-checkpoint',
      size: 70000,
    });
    expect(parseLogPath('x-checkpoints/0')).toEqual({ kind: 'archived-checkpoint', size: 0 });
  });

  it('round-trips generated paths', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 63 }),
        fc.maxSafeNat(),
        fc.integer({ min: 1, max: 256 }),
        (level, index, width) => {
          expect(parseLogPath(tilePath(level, index, width))).toEqual({
            kind: 'tile',
            level,
            index,
            width,
          });
          expect(parseLogPath(entryBundlePath(index, width))).toEqual({
            kind: 'bundle',
            index,
            width,
          });
        },
      ),
    );
  });

  it.each([
    '',
    '/checkpoint',
    'checkpoint/',
    'tile/00/000', // leading zero level
    'tile/64/000', // level out of range
    'tile/0/000.p/0', // empty tile
    'tile/0/000.p/256', // full width must not use .p
    'tile/0/000.p/017', // leading zero width
    'tile/0/x000/001',
    'tile/0',
    'tile/entries',
    'tile/entries/000.p/',
    'tile/x/000',
    'x-checkpoints/007',
    'x-checkpoints/',
    'x-checkpoints/-1',
    '../checkpoint',
    'tile/0/000/../001',
  ])('rejects %j', (p) => {
    expect(parseLogPath(p)).toBeNull();
  });
});
