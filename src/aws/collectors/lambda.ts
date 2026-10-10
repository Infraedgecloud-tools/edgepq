import { LambdaClient, paginateListFunctions } from '@aws-sdk/client-lambda';
import type { Collector } from '../types.ts';
import { clientConfig, resource } from './helpers.ts';

export const lambda: Collector = {
  service: 'lambda',
  async run(ctx) {
    const client = new LambdaClient(clientConfig(ctx));
    const resources = [];
    for await (const page of paginateListFunctions({ client }, {})) {
      for (const f of page.Functions ?? []) {
        if (!f.FunctionArn) continue;
        resources.push(resource(ctx, 'aws_lambda_function', f.FunctionArn, {
          function_name: f.FunctionName ?? null,
          runtime: f.Runtime ?? null,
          architectures: f.Architectures ?? [],
          layers: (f.Layers ?? []).map((l) => l.Arn).filter((a): a is string => !!a),
        }));
      }
    }
    return { resources };
  },
};
