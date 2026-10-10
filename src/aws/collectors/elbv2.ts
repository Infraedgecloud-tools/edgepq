import { ElasticLoadBalancingV2Client, paginateDescribeListeners, paginateDescribeLoadBalancers } from '@aws-sdk/client-elastic-load-balancing-v2';
import type { Collector } from '../types.ts';
import { clientConfig, resource } from './helpers.ts';

/* Every listener of every ALB and NLB. The rule only looks at HTTPS and TLS
   listeners, but the others are collected so the inventory is complete. */
export const elbv2: Collector = {
  service: 'elasticloadbalancing',
  async run(ctx) {
    const client = new ElasticLoadBalancingV2Client(clientConfig(ctx));
    const resources = [];
    for await (const page of paginateDescribeLoadBalancers({ client }, {})) {
      for (const lb of page.LoadBalancers ?? []) {
        if (!lb.LoadBalancerArn) continue;
        for await (const lp of paginateDescribeListeners({ client }, { LoadBalancerArn: lb.LoadBalancerArn })) {
          for (const l of lp.Listeners ?? []) {
            if (!l.ListenerArn) continue;
            resources.push(resource(ctx, 'aws_lb_listener', l.ListenerArn, {
              load_balancer_arn: lb.LoadBalancerArn,
              load_balancer_type: lb.Type ?? null,
              port: l.Port ?? null,
              protocol: l.Protocol ?? null,
              ...(l.SslPolicy ? { ssl_policy: l.SslPolicy } : {}),
            }));
          }
        }
      }
    }
    return { resources };
  },
};
