import type { Collector } from '../types.ts';
import { elbv2 } from './elbv2.ts';
import { cloudfront } from './cloudfront.ts';
import { apigateway, apigatewayv2 } from './apigateway.ts';
import { kms } from './kms.ts';
import { acm, acmpca } from './certificates.ts';
import { cloudtrail } from './cloudtrail.ts';

export const COLLECTORS: Collector[] = [elbv2, cloudfront, apigateway, apigatewayv2, kms, acm, acmpca, cloudtrail];
