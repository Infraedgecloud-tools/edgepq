import { APIGatewayClient, paginateGetDomainNames, paginateGetRestApis } from '@aws-sdk/client-api-gateway';
import { ApiGatewayV2Client, GetDomainNamesCommand } from '@aws-sdk/client-apigatewayv2';
import type { Collector } from '../types.ts';
import { clientConfig, resource } from './helpers.ts';

/* REST API custom domains and the APIs' own execute-api endpoints. The API
   response carries securityPolicy only when it was set, which matches the
   Terraform shape: absent means the service default, and the rules apply it. */
export const apigateway: Collector = {
  service: 'apigateway',
  async run(ctx) {
    const client = new APIGatewayClient(clientConfig(ctx));
    const resources = [];
    const region = ctx.scope.region;
    for await (const page of paginateGetDomainNames({ client }, {})) {
      for (const d of page.items ?? []) {
        if (!d.domainName) continue;
        const arn = d.domainNameArn ?? `arn:aws:apigateway:${region}::/domainnames/${d.domainName}`;
        resources.push(resource(ctx, 'aws_api_gateway_domain_name', arn, {
          domain_name: d.domainName,
          ...(d.securityPolicy ? { security_policy: d.securityPolicy } : {}),
          ...(d.endpointAccessMode ? { endpoint_access_mode: d.endpointAccessMode } : {}),
          ...(d.mutualTlsAuthentication?.truststoreUri ? { mutual_tls_authentication: [{ truststore_uri: d.mutualTlsAuthentication.truststoreUri }] } : {}),
          /* No default is assumed: the rule treats a missing type as could-not-check. */
          ...(d.endpointConfiguration?.types ? { endpoint_configuration: [{ types: d.endpointConfiguration.types }] } : {}),
        }));
      }
    }
    for await (const page of paginateGetRestApis({ client }, {})) {
      for (const a of page.items ?? []) {
        if (!a.id) continue;
        resources.push(resource(ctx, 'aws_api_gateway_rest_api', `arn:aws:apigateway:${region}::/restapis/${a.id}`, {
          name: a.name ?? null,
          ...(a.securityPolicy ? { security_policy: a.securityPolicy } : {}),
          ...(a.endpointAccessMode ? { endpoint_access_mode: a.endpointAccessMode } : {}),
          disable_execute_api_endpoint: a.disableExecuteApiEndpoint ?? false,
          endpoint_configuration: [{ types: a.endpointConfiguration?.types ?? ['EDGE'] }],
        }));
      }
    }
    return { resources };
  },
};

export const apigatewayv2: Collector = {
  service: 'apigatewayv2',
  async run(ctx) {
    const client = new ApiGatewayV2Client(clientConfig(ctx));
    const resources = [];
    let next: string | undefined;
    do {
      const page = await client.send(new GetDomainNamesCommand(next ? { NextToken: next } : {}));
      for (const d of page.Items ?? []) {
        if (!d.DomainName) continue;
        const cfg = d.DomainNameConfigurations?.[0];
        resources.push(resource(ctx, 'aws_apigatewayv2_domain_name', d.DomainNameArn ?? `arn:aws:apigateway:${ctx.scope.region}::/domainnames/${d.DomainName}`, {
          domain_name: d.DomainName,
          domain_name_configuration: [{
            ...(cfg?.SecurityPolicy ? { security_policy: cfg.SecurityPolicy } : {}),
            ...(cfg?.EndpointType ? { endpoint_type: cfg.EndpointType } : {}),
          }],
        }));
      }
      next = page.NextToken;
    } while (next);
    return { resources };
  },
};
