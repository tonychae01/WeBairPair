declare module "edmonds-blossom-fixed" {
  export default function blossom(
    edges: Array<[number, number, number]>,
    maxCardinality?: boolean,
  ): number[];
}
