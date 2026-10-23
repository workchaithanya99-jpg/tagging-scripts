"""
AWS Tag Compliance Checker & Auto-Tagger  -  Prod-Safe with Approval Gate
==========================================================================

  PHASE 1  SCAN     Read-only, parallel. Builds a plan of missing tags.
  APPROVAL GATE     Prints the plan, waits for "yes" (skipped with --yes).
  PHASE 2  APPLY    Parallel. Tags only the resources in the plan.

RULES:
  - A tag is added ONLY if its KEY is absent. Existing keys (even with an empty
    value) are never overwritten.
  - Databases are NOT tagged, except DynamoDB (no RDS, Aurora, ElastiCache ...).
  - Customer-managed KMS keys and Glue resources are tagged. AWS-managed KMS
    keys are skipped (AWS does not allow tagging them).

USAGE:
  python tag-script.py                         # regions from SCAN_REGIONS
  python tag-script.py us-east-2 eu-central-1  # override regions
  python tag-script.py --yes                   # skip approval prompt (cron)
  python tag-script.py --workers=48            # parallel workers (default 32)
  python tag-script.py --quiet                 # no per-resource scan log
"""

import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# =============================================================================
# SETTINGS
# =============================================================================
STATIC_TAGS = {
    "map-migrated": "migM9SPIUCDZT",
}

AUTO_APPROVE = "--yes" in sys.argv
LIVE = "--quiet" not in sys.argv
WORKERS = int(next((a.split("=")[1] for a in sys.argv if a.startswith("--workers=")), 32))
LOOKUP_WORKERS = 16     # per-resource tag lookups inside one scanner

REGIONAL_SERVICES = [
    "EC2 Instances", "EBS Volumes", "EBS Snapshots", "Security Groups", "VPCs",
    "Subnets", "Route Tables", "Internet Gateways", "NAT Gateways", "Elastic IPs",
    "Network Interfaces", "Key Pairs", "AMIs",
    "Lambda Functions",
    # "RDS Instances",          # database - removed
    # "RDS Clusters",           # database - removed
    # "ElastiCache Clusters",   # database - removed
    "Load Balancers", "Target Groups", "ECS Clusters", "ECS Services", "EKS Clusters",
    "DynamoDB Tables",          # the ONLY database that is tagged
    "SQS Queues", "SNS Topics", "Secrets Manager", "CloudWatch Log Groups",
    "Kinesis Streams", "Step Functions", "API Gateway (v2)", "ECR Repositories",
    "SSM Parameters", "Auto Scaling Groups", "OpenSearch Domains", "MSK Clusters",
    "SES", "Glue", "KMS (customer managed)",
]

GLOBAL_SERVICES = [
    "S3 Buckets", "IAM Roles", "IAM Policies", "CloudFront Distributions",
]

SCAN_REGIONS = [
    # "us-east-1",
    "us-east-2",
    # "us-west-1",
    "us-west-2",
    # "eu-west-1",
    "eu-central-1",
    "mx-central-1",
    # "ap-south-1",
    # "ap-southeast-1",
    # "ap-northeast-1",
]


def get_regions() -> list:
    cli = [a for a in sys.argv[1:] if not a.startswith("--")]
    if cli:
        print(f"\n  Regions from command-line args: {', '.join(cli)}", flush=True)
        return cli
    return SCAN_REGIONS


# =============================================================================
# CLIENTS / HELPERS
# =============================================================================
_CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"},
              connect_timeout=15, read_timeout=60, max_pool_connections=128)
_SESSION = boto3.session.Session()
_CLIENTS = {}
_CLIENT_LOCK = threading.Lock()
_LOCK = threading.Lock()
_TL = threading.local()

PLAN = []
ERRORS = []
EVAL_COUNT = [0]
_ACCOUNT_ID = None


def _client(service, region_name=None):
    key = (service, region_name)
    with _CLIENT_LOCK:
        c = _CLIENTS.get(key)
        if c is None:
            c = _SESSION.client(service, region_name=region_name, config=_CFG)
            _CLIENTS[key] = c
        return c


def account_id() -> str:
    global _ACCOUNT_ID
    with _LOCK:
        if _ACCOUNT_ID is None:
            _ACCOUNT_ID = _client("sts").get_caller_identity()["Account"]
        return _ACCOUNT_ID


def _pmap(fn, items, workers=LOOKUP_WORKERS):
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(fn, items))


def _collect(fn, key, tok_in="NextToken", tok_out="NextToken", **kw):
    """Manual pagination for APIs without reliable paginators."""
    out, token = [], None
    while True:
        if token:
            kw[tok_in] = token
        resp = fn(**kw)
        out.extend(resp.get(key, []))
        token = resp.get(tok_out)
        if not token:
            return out


def section(title):
    print(f"\n{'=' * 70}\n  {title}\n{'=' * 70}", flush=True)


def subsection(title):
    print(f"\n  -- {title} {'-' * max(1, 55 - len(title))}", flush=True)


def scan_log(msg):
    if LIVE:
        print(f"  [SCAN]    {msg}", flush=True)


def ok_log(msg):
    if LIVE:
        print(f"  [OK]      {msg}", flush=True)


def warn_log(msg):
    with _LOCK:
        ERRORS.append(f"[WARN]  {msg}")
    print(f"  [WARN]    {msg}", flush=True)


def err_log(msg):
    with _LOCK:
        ERRORS.append(f"[ERROR] {msg}")
    if LIVE:
        print(f"  [ERROR]   {msg}", flush=True)


# =============================================================================
# TAG UTILITIES
# =============================================================================
def missing_tags(existing: dict, required: dict) -> dict:
    """Only keys that do not exist at all. Existing keys are never touched."""
    return {k: v for k, v in required.items() if k not in existing}


def kv_to_dict(tag_list) -> dict:
    return {t["Key"]: t["Value"] for t in (tag_list or [])}


def lkv_to_dict(tag_list) -> dict:
    return {t["key"]: t["value"] for t in (tag_list or [])}


def dict_to_kv(d: dict) -> list:
    return [{"Key": k, "Value": v} for k, v in d.items()]


def dict_to_lkv(d: dict) -> list:
    return [{"key": k, "value": v} for k, v in d.items()]


def evaluate(rtype, rid, fallback_name, existing, region, service, apply_fn):
    """READ-ONLY: compare tags, add to PLAN if a key is absent."""
    with _LOCK:
        EVAL_COUNT[0] += 1
    existing = existing or {}
    name = existing.get("Name") or fallback_name
    missing = missing_tags(existing, STATIC_TAGS)
    if missing:
        scan_log(f"{region:<13} {rtype}  [{name}]  ({rid})  needs -> {list(missing)}")
        with _LOCK:
            PLAN.append({"type": rtype, "id": rid, "name": name, "region": region,
                         "service": service, "missing": missing, "apply_fn": apply_fn})
    else:
        ok_log(f"{region:<13} {rtype}  [{name}]  ({rid})  already tagged")


def ec2_tagger(region, rid, missing):
    def _apply():
        _client("ec2", region_name=region).create_tags(
            Resources=[rid], Tags=dict_to_kv(missing))
    return _apply


def _tags_for(items, fn, label):
    """items: [(id, name)]. fn(id) -> existing tag dict. Runs lookups in parallel."""
    def one(it):
        try:
            return it, fn(it[0]), None
        except Exception as e:
            return it, None, e
    out = []
    for it, existing, exc in _pmap(one, items):
        if exc:
            err_log(f"{label}  [{it[1]}]  -- {exc}")
        else:
            out.append((it[0], it[1], existing))
    return out


# =============================================================================
# PHASE 1 - SCAN FUNCTIONS (READ-ONLY)
# =============================================================================
def scan_ec2_instances(region):
    ec2 = _client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_instances").paginate():
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                if inst["State"]["Name"] == "terminated":
                    continue
                rid = inst["InstanceId"]
                existing = kv_to_dict(inst.get("Tags", []))
                evaluate("EC2 Instance", rid, rid, existing, region, "EC2",
                         ec2_tagger(region, rid, missing_tags(existing, STATIC_TAGS)))


def _ec2_simple(region, api, list_key, id_key, tag_key, rtype, service, name_key=None,
                **paginate_kw):
    ec2 = _client("ec2", region_name=region)
    for page in ec2.get_paginator(api).paginate(**paginate_kw):
        for r in page[list_key]:
            rid = r[id_key]
            existing = kv_to_dict(r.get(tag_key, []))
            evaluate(rtype, rid, r.get(name_key, rid) if name_key else rid, existing,
                     region, service,
                     ec2_tagger(region, rid, missing_tags(existing, STATIC_TAGS)))


def scan_ebs_volumes(region):
    _ec2_simple(region, "describe_volumes", "Volumes", "VolumeId", "Tags",
                "EBS Volume", "EBS")


def scan_ebs_snapshots(region):
    _ec2_simple(region, "describe_snapshots", "Snapshots", "SnapshotId", "Tags",
                "EBS Snapshot", "EBSSnapshot", OwnerIds=[account_id()])


def scan_security_groups(region):
    _ec2_simple(region, "describe_security_groups", "SecurityGroups", "GroupId", "Tags",
                "Security Group", "SecurityGroup", name_key="GroupName")


def scan_vpcs(region):
    _ec2_simple(region, "describe_vpcs", "Vpcs", "VpcId", "Tags", "VPC", "VPC")


def scan_subnets(region):
    _ec2_simple(region, "describe_subnets", "Subnets", "SubnetId", "Tags",
                "Subnet", "Subnet")


def scan_route_tables(region):
    _ec2_simple(region, "describe_route_tables", "RouteTables", "RouteTableId", "Tags",
                "Route Table", "RouteTable")


def scan_internet_gateways(region):
    _ec2_simple(region, "describe_internet_gateways", "InternetGateways",
                "InternetGatewayId", "Tags", "Internet Gateway", "InternetGateway")


def scan_nat_gateways(region):
    _ec2_simple(region, "describe_nat_gateways", "NatGateways", "NatGatewayId", "Tags",
                "NAT Gateway", "NATGateway",
                Filter=[{"Name": "state", "Values": ["available", "pending"]}])


def scan_network_interfaces(region):
    _ec2_simple(region, "describe_network_interfaces", "NetworkInterfaces",
                "NetworkInterfaceId", "TagSet", "Network Interface", "NetworkInterface")


def scan_elastic_ips(region):
    ec2 = _client("ec2", region_name=region)
    for addr in ec2.describe_addresses()["Addresses"]:
        rid = addr.get("AllocationId")
        if not rid:
            continue
        existing = kv_to_dict(addr.get("Tags", []))
        evaluate("Elastic IP", rid, addr.get("PublicIp", rid), existing, region,
                 "ElasticIP", ec2_tagger(region, rid, missing_tags(existing, STATIC_TAGS)))


def scan_key_pairs(region):
    ec2 = _client("ec2", region_name=region)
    for kp in ec2.describe_key_pairs().get("KeyPairs", []):
        rid = kp.get("KeyPairId")
        if not rid:
            continue
        existing = kv_to_dict(kp.get("Tags", []))
        evaluate("Key Pair", rid, kp["KeyName"], existing, region, "KeyPair",
                 ec2_tagger(region, rid, missing_tags(existing, STATIC_TAGS)))


def scan_amis(region):
    ec2 = _client("ec2", region_name=region)
    for img in ec2.describe_images(Owners=[account_id()])["Images"]:
        rid = img["ImageId"]
        existing = kv_to_dict(img.get("Tags", []))
        evaluate("AMI", rid, img.get("Name", rid), existing, region, "AMI",
                 ec2_tagger(region, rid, missing_tags(existing, STATIC_TAGS)))


# --- S3 (global) ---
def scan_s3_buckets():
    s3 = _client("s3")
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]

    def one(bname):
        try:
            loc = s3.get_bucket_location(Bucket=bname)
            region = loc.get("LocationConstraint") or "us-east-1"
            if region == "EU":
                region = "eu-west-1"
            rs3 = _client("s3", region_name=region)
            try:
                existing = kv_to_dict(rs3.get_bucket_tagging(Bucket=bname).get("TagSet", []))
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchTagSet":
                    raise
                existing = {}

            # put_bucket_tagging REPLACES the whole set, so tags are re-read at apply
            # time and merged. Existing keys always win.
            def _apply(_b=bname, _rg=region):
                c = _client("s3", region_name=_rg)
                try:
                    cur = kv_to_dict(c.get_bucket_tagging(Bucket=_b).get("TagSet", []))
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchTagSet":
                        raise
                    cur = {}
                final = {**missing_tags(cur, STATIC_TAGS), **cur}
                if final == cur:
                    return
                c.put_bucket_tagging(Bucket=_b, Tagging={"TagSet": dict_to_kv(final)})

            evaluate("S3 Bucket", bname, bname, existing, region, "S3", _apply)
        except Exception as e:
            err_log(f"S3 Bucket  [{bname}]  -- {e}")

    _pmap(one, buckets)


# --- LAMBDA ---
def scan_lambda_functions(region):
    lmb = _client("lambda", region_name=region)
    items = [(fn["FunctionArn"], fn["FunctionName"])
             for page in lmb.get_paginator("list_functions").paginate()
             for fn in page["Functions"]]
    for arn, fname, existing in _tags_for(
            items, lambda a: lmb.list_tags(Resource=a).get("Tags", {}), "Lambda"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("Lambda", arn, fname, existing, region, "Lambda",
                 lambda _a=arn, _m=missing, _rg=region:
                     _client("lambda", region_name=_rg).tag_resource(Resource=_a, Tags=_m))


# --- LOAD BALANCERS / TARGET GROUPS ---
def scan_load_balancers(region):
    elb = _client("elbv2", region_name=region)
    tmap = {"application": "ALB", "network": "NLB", "gateway": "GWLB"}
    for page in elb.get_paginator("describe_load_balancers").paginate():
        for lb in page["LoadBalancers"]:
            arn, lname = lb["LoadBalancerArn"], lb["LoadBalancerName"]
            ltype = tmap.get(lb["Type"], lb["Type"].upper())
            try:
                d = elb.describe_tags(ResourceArns=[arn])["TagDescriptions"]
                existing = kv_to_dict(d[0].get("Tags", [])) if d else {}
                missing = missing_tags(existing, STATIC_TAGS)
                evaluate(f"Load Balancer ({ltype})", arn, lname, existing, region, ltype,
                         lambda _a=arn, _m=missing, _rg=region:
                             _client("elbv2", region_name=_rg)
                                 .add_tags(ResourceArns=[_a], Tags=dict_to_kv(_m)))
            except Exception as e:
                err_log(f"Load Balancer  [{lname}]  -- {e}")


def scan_target_groups(region):
    elb = _client("elbv2", region_name=region)
    for page in elb.get_paginator("describe_target_groups").paginate():
        for tg in page["TargetGroups"]:
            arn, tname = tg["TargetGroupArn"], tg["TargetGroupName"]
            try:
                d = elb.describe_tags(ResourceArns=[arn])["TagDescriptions"]
                existing = kv_to_dict(d[0].get("Tags", [])) if d else {}
                missing = missing_tags(existing, STATIC_TAGS)
                evaluate("Target Group", arn, tname, existing, region, "TargetGroup",
                         lambda _a=arn, _m=missing, _rg=region:
                             _client("elbv2", region_name=_rg)
                                 .add_tags(ResourceArns=[_a], Tags=dict_to_kv(_m)))
            except Exception as e:
                err_log(f"Target Group  [{tname}]  -- {e}")


# --- ECS / EKS ---
def scan_ecs_clusters(region):
    ecs = _client("ecs", region_name=region)
    arns = [a for p in ecs.get_paginator("list_clusters").paginate() for a in p["clusterArns"]]
    for i in range(0, len(arns), 100):
        for c in ecs.describe_clusters(clusters=arns[i:i + 100], include=["TAGS"])["clusters"]:
            arn, cname = c["clusterArn"], c["clusterName"]
            existing = lkv_to_dict(c.get("tags", []))
            missing = missing_tags(existing, STATIC_TAGS)
            evaluate("ECS Cluster", arn, cname, existing, region, "ECSCluster",
                     lambda _a=arn, _m=missing, _rg=region:
                         _client("ecs", region_name=_rg)
                             .tag_resource(resourceArn=_a, tags=dict_to_lkv(_m)))


def scan_ecs_services(region):
    ecs = _client("ecs", region_name=region)
    clusters = [a for p in ecs.get_paginator("list_clusters").paginate() for a in p["clusterArns"]]
    for cluster in clusters:
        svc_arns = [a for p in ecs.get_paginator("list_services").paginate(cluster=cluster)
                    for a in p["serviceArns"]]
        for i in range(0, len(svc_arns), 10):
            resp = ecs.describe_services(cluster=cluster, services=svc_arns[i:i + 10],
                                         include=["TAGS"])
            for svc in resp["services"]:
                arn, sname = svc["serviceArn"], svc["serviceName"]
                existing = lkv_to_dict(svc.get("tags", []))
                missing = missing_tags(existing, STATIC_TAGS)
                evaluate("ECS Service", arn, sname, existing, region, "ECSService",
                         lambda _a=arn, _m=missing, _rg=region:
                             _client("ecs", region_name=_rg)
                                 .tag_resource(resourceArn=_a, tags=dict_to_lkv(_m)))


def scan_eks_clusters(region):
    eks = _client("eks", region_name=region)
    for page in eks.get_paginator("list_clusters").paginate():
        for cname in page["clusters"]:
            cluster = eks.describe_cluster(name=cname)["cluster"]
            arn = cluster["arn"]
            existing = cluster.get("tags", {})
            missing = missing_tags(existing, STATIC_TAGS)
            evaluate("EKS Cluster", arn, cname, existing, region, "EKS",
                     lambda _a=arn, _m=missing, _rg=region:
                         _client("eks", region_name=_rg).tag_resource(resourceArn=_a, tags=_m))


# --- DYNAMODB (the only database that is tagged) ---
def scan_dynamodb_tables(region):
    ddb = _client("dynamodb", region_name=region)
    acct = account_id()
    items = [(f"arn:aws:dynamodb:{region}:{acct}:table/{t}", t)
             for p in ddb.get_paginator("list_tables").paginate() for t in p["TableNames"]]
    for arn, tname, existing in _tags_for(
            items,
            lambda a: kv_to_dict(_collect(ddb.list_tags_of_resource, "Tags", ResourceArn=a)),
            "DynamoDB"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("DynamoDB", arn, tname, existing, region, "DynamoDB",
                 lambda _a=arn, _m=missing, _rg=region:
                     _client("dynamodb", region_name=_rg)
                         .tag_resource(ResourceArn=_a, Tags=dict_to_kv(_m)))


# --- SQS / SNS ---
def scan_sqs_queues(region):
    sqs = _client("sqs", region_name=region)
    urls = []
    for p in sqs.get_paginator("list_queues").paginate():
        urls.extend(p.get("QueueUrls", []))
    items = [(u, u.split("/")[-1]) for u in urls]
    for url, qname, existing in _tags_for(
            items, lambda u: sqs.list_queue_tags(QueueUrl=u).get("Tags", {}), "SQS Queue"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("SQS Queue", url, qname, existing, region, "SQS",
                 lambda _u=url, _m=missing, _rg=region:
                     _client("sqs", region_name=_rg).tag_queue(QueueUrl=_u, Tags=_m))


def scan_sns_topics(region):
    sns = _client("sns", region_name=region)
    items = [(t["TopicArn"], t["TopicArn"].split(":")[-1])
             for p in sns.get_paginator("list_topics").paginate() for t in p["Topics"]]
    for arn, tname, existing in _tags_for(
            items,
            lambda a: kv_to_dict(sns.list_tags_for_resource(ResourceArn=a).get("Tags", [])),
            "SNS Topic"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("SNS Topic", arn, tname, existing, region, "SNS",
                 lambda _a=arn, _m=missing, _rg=region:
                     _client("sns", region_name=_rg)
                         .tag_resource(ResourceArn=_a, Tags=dict_to_kv(_m)))


def scan_secrets_manager(region):
    sm = _client("secretsmanager", region_name=region)
    for page in sm.get_paginator("list_secrets").paginate():
        for s in page["SecretList"]:
            arn, sname = s["ARN"], s["Name"]
            existing = kv_to_dict(s.get("Tags", []))
            missing = missing_tags(existing, STATIC_TAGS)
            evaluate("Secret", arn, sname, existing, region, "SecretsManager",
                     lambda _a=arn, _m=missing, _rg=region:
                         _client("secretsmanager", region_name=_rg)
                             .tag_resource(SecretId=_a, Tags=dict_to_kv(_m)))


# --- CLOUDWATCH LOG GROUPS ---
def scan_cloudwatch_log_groups(region):
    logs = _client("logs", region_name=region)
    items = [(lg["logGroupName"], lg["logGroupName"])
             for p in logs.get_paginator("describe_log_groups").paginate()
             for lg in p["logGroups"]]
    for name, _, existing in _tags_for(
            items, lambda n: logs.list_tags_log_group(logGroupName=n).get("tags", {}),
            "Log Group"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("CloudWatch Log Group", name, name, existing, region, "CloudWatchLogs",
                 lambda _n=name, _m=missing, _rg=region:
                     _client("logs", region_name=_rg).tag_log_group(logGroupName=_n, tags=_m))


def scan_kinesis_streams(region):
    kin = _client("kinesis", region_name=region)
    names = []
    for p in kin.get_paginator("list_streams").paginate():
        names.extend(p.get("StreamNames", []))
    for stream, _, existing in _tags_for(
            [(n, n) for n in names],
            lambda n: kv_to_dict(kin.list_tags_for_stream(StreamName=n).get("Tags", [])),
            "Kinesis Stream"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("Kinesis Stream", stream, stream, existing, region, "Kinesis",
                 lambda _s=stream, _m=missing, _rg=region:
                     _client("kinesis", region_name=_rg).add_tags_to_stream(StreamName=_s, Tags=_m))


def scan_step_functions(region):
    sfn = _client("stepfunctions", region_name=region)
    items = [(sm["stateMachineArn"], sm["name"])
             for p in sfn.get_paginator("list_state_machines").paginate()
             for sm in p["stateMachines"]]
    for arn, sname, existing in _tags_for(
            items,
            lambda a: lkv_to_dict(sfn.list_tags_for_resource(resourceArn=a).get("tags", [])),
            "Step Function"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("Step Function", arn, sname, existing, region, "StepFunctions",
                 lambda _a=arn, _m=missing, _rg=region:
                     _client("stepfunctions", region_name=_rg)
                         .tag_resource(resourceArn=_a, tags=dict_to_lkv(_m)))


# --- IAM (global) ---
def scan_iam_roles():
    iam = _client("iam")
    items = []
    for p in iam.get_paginator("list_roles").paginate():
        for role in p["Roles"]:
            if role["RoleName"].startswith("AWS") or "/aws-service-role/" in role["Arn"]:
                continue
            items.append((role["RoleName"], role["RoleName"]))
    for rname, _, existing in _tags_for(
            items, lambda n: kv_to_dict(iam.list_role_tags(RoleName=n).get("Tags", [])),
            "IAM Role"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("IAM Role", rname, rname, existing, "global", "IAMRole",
                 lambda _n=rname, _m=missing:
                     _client("iam").tag_role(RoleName=_n, Tags=dict_to_kv(_m)))


def scan_iam_policies():
    iam = _client("iam")
    items = [(p["Arn"], p["PolicyName"])
             for page in iam.get_paginator("list_policies").paginate(Scope="Local")
             for p in page["Policies"]]
    for arn, pname, existing in _tags_for(
            items, lambda a: kv_to_dict(iam.list_policy_tags(PolicyArn=a).get("Tags", [])),
            "IAM Policy"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("IAM Policy", arn, pname, existing, "global", "IAMPolicy",
                 lambda _a=arn, _m=missing:
                     _client("iam").tag_policy(PolicyArn=_a, Tags=dict_to_kv(_m)))


def scan_api_gateway(region):
    apigw = _client("apigatewayv2", region_name=region)
    for api in _collect(apigw.get_apis, "Items"):
        api_id = api["ApiId"]
        arn = f"arn:aws:apigateway:{region}::/apis/{api_id}"
        existing = api.get("Tags", {})
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("API Gateway", arn, api.get("Name", api_id), existing, region, "APIGateway",
                 lambda _a=arn, _m=missing, _rg=region:
                     _client("apigatewayv2", region_name=_rg)
                         .tag_resource(ResourceArn=_a, Tags=_m))


def scan_cloudfront_distributions():
    cf = _client("cloudfront")
    for page in cf.get_paginator("list_distributions").paginate():
        for dist in page.get("DistributionList", {}).get("Items", []) or []:
            arn, did = dist["ARN"], dist["Id"]
            try:
                existing = kv_to_dict(
                    cf.list_tags_for_resource(Resource=arn)["Tags"].get("Items", []))
                missing = missing_tags(existing, STATIC_TAGS)
                evaluate("CloudFront", arn, did, existing, "global", "CloudFront",
                         lambda _a=arn, _m=missing:
                             _client("cloudfront")
                                 .tag_resource(Resource=_a, Tags={"Items": dict_to_kv(_m)}))
            except Exception as e:
                err_log(f"CloudFront  [{did}]  -- {e}")


def scan_ecr_repositories(region):
    ecr = _client("ecr", region_name=region)
    items = [(r["repositoryArn"], r["repositoryName"])
             for p in ecr.get_paginator("describe_repositories").paginate()
             for r in p["repositories"]]
    for arn, rname, existing in _tags_for(
            items,
            lambda a: kv_to_dict(ecr.list_tags_for_resource(resourceArn=a).get("tags", [])),
            "ECR Repository"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("ECR Repository", arn, rname, existing, region, "ECR",
                 lambda _a=arn, _m=missing, _rg=region:
                     _client("ecr", region_name=_rg)
                         .tag_resource(resourceArn=_a, tags=dict_to_kv(_m)))


def scan_ssm_parameters(region):
    ssm = _client("ssm", region_name=region)
    names = [p["Name"] for page in ssm.get_paginator("describe_parameters").paginate()
             for p in page["Parameters"]]
    for pname, _, existing in _tags_for(
            [(n, n) for n in names],
            lambda n: kv_to_dict(ssm.list_tags_for_resource(
                ResourceType="Parameter", ResourceId=n).get("TagList", [])),
            "SSM Parameter"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("SSM Parameter", pname, pname, existing, region, "SSM",
                 lambda _n=pname, _m=missing, _rg=region:
                     _client("ssm", region_name=_rg).add_tags_to_resource(
                         ResourceType="Parameter", ResourceId=_n, Tags=dict_to_kv(_m)))


def scan_autoscaling_groups(region):
    asg = _client("autoscaling", region_name=region)
    for page in asg.get_paginator("describe_auto_scaling_groups").paginate():
        for group in page["AutoScalingGroups"]:
            gname = group["AutoScalingGroupName"]
            existing = kv_to_dict(group.get("Tags", []))
            missing = missing_tags(existing, STATIC_TAGS)
            evaluate("Auto Scaling Group", gname, gname, existing, region, "AutoScaling",
                     lambda _g=gname, _m=missing, _rg=region:
                         _client("autoscaling", region_name=_rg).create_or_update_tags(Tags=[
                             {"ResourceId": _g, "ResourceType": "auto-scaling-group",
                              "Key": k, "Value": v, "PropagateAtLaunch": True}
                             for k, v in _m.items()]))


def scan_opensearch_domains(region):
    osc = _client("opensearch", region_name=region)
    for domain in osc.list_domain_names().get("DomainNames", []):
        dname = domain["DomainName"]
        try:
            arn = osc.describe_domain(DomainName=dname)["DomainStatus"]["ARN"]
            existing = kv_to_dict(osc.list_tags(ARN=arn).get("TagList", []))
            missing = missing_tags(existing, STATIC_TAGS)
            evaluate("OpenSearch Domain", arn, dname, existing, region, "OpenSearch",
                     lambda _a=arn, _m=missing, _rg=region:
                         _client("opensearch", region_name=_rg)
                             .add_tags(ARN=_a, TagList=dict_to_kv(_m)))
        except Exception as e:
            err_log(f"OpenSearch  [{dname}]  -- {e}")


def scan_msk_clusters(region):
    msk = _client("kafka", region_name=region)
    for page in msk.get_paginator("list_clusters_v2").paginate():
        for c in page.get("ClusterInfoList", []):
            arn, cname = c["ClusterArn"], c["ClusterName"]
            existing = c.get("Tags") or msk.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
            missing = missing_tags(existing, STATIC_TAGS)
            evaluate("MSK Cluster", arn, cname, existing, region, "MSK",
                     lambda _a=arn, _m=missing, _rg=region:
                         _client("kafka", region_name=_rg).tag_resource(ResourceArn=_a, Tags=_m))


# --- SES (v2): identities, configuration sets, contact lists, dedicated IP pools ---
def scan_ses(region):
    s = _client("sesv2", region_name=region)
    base = f"arn:aws:ses:{region}:{account_id()}"
    items = []
    for i in _collect(s.list_email_identities, "EmailIdentities"):
        items.append((f"{base}:identity/{i['IdentityName']}", i["IdentityName"], "SES Identity"))
    for n in _collect(s.list_configuration_sets, "ConfigurationSets"):
        items.append((f"{base}:configuration-set/{n}", n, "SES Configuration Set"))
    for c in _collect(s.list_contact_lists, "ContactLists"):
        n = c["ContactListName"]
        items.append((f"{base}:contact-list/{n}", n, "SES Contact List"))
    for n in _collect(s.list_dedicated_ip_pools, "DedicatedIpPools"):
        items.append((f"{base}:dedicated-ip-pool/{n}", n, "SES Dedicated IP Pool"))
    kinds = {a: k for a, _, k in items}
    for arn, name, existing in _tags_for(
            [(a, n) for a, n, _ in items],
            lambda a: kv_to_dict(s.list_tags_for_resource(ResourceArn=a).get("Tags", [])),
            "SES"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate(kinds[arn], arn, name, existing, region, "SES",
                 lambda _a=arn, _m=missing, _rg=region:
                     _client("sesv2", region_name=_rg)
                         .tag_resource(ResourceArn=_a, Tags=dict_to_kv(_m)))


# --- GLUE: databases, crawlers, jobs, triggers, workflows ---
def scan_glue(region):
    g = _client("glue", region_name=region)
    base = f"arn:aws:glue:{region}:{account_id()}"
    items = []
    for d in _collect(g.get_databases, "DatabaseList"):
        if d.get("TargetDatabase"):
            continue                      # resource links cannot be tagged
        items.append(("Glue Database", f"{base}:database/{d['Name']}", d["Name"]))
    for c in _collect(g.get_crawlers, "Crawlers"):
        items.append(("Glue Crawler", f"{base}:crawler/{c['Name']}", c["Name"]))
    for n in _collect(g.list_jobs, "JobNames"):
        items.append(("Glue Job", f"{base}:job/{n}", n))
    for n in _collect(g.list_triggers, "TriggerNames"):
        items.append(("Glue Trigger", f"{base}:trigger/{n}", n))
    for n in _collect(g.list_workflows, "Workflows"):
        items.append(("Glue Workflow", f"{base}:workflow/{n}", n))
    kinds = {a: k for k, a, _ in items}
    for arn, name, existing in _tags_for(
            [(a, n) for _, a, n in items],
            lambda a: g.get_tags(ResourceArn=a).get("Tags", {}), "Glue"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate(kinds[arn], arn, name, existing, region, "Glue",
                 lambda _a=arn, _m=missing, _rg=region:
                     _client("glue", region_name=_rg).tag_resource(ResourceArn=_a, TagsToAdd=_m))


# --- KMS: customer-managed keys only ---
def scan_kms(region):
    k = _client("kms", region_name=region)
    key_ids = [x["KeyId"] for x in _collect(k.list_keys, "Keys", "Marker", "NextMarker")]

    def describe(kid):
        try:
            return k.describe_key(KeyId=kid)["KeyMetadata"]
        except Exception as e:
            err_log(f"KMS key  [{kid}]  -- {e}")
            return None

    keys = []
    for m in _pmap(describe, key_ids):
        if not m or m.get("KeyManager") != "CUSTOMER":
            continue                      # AWS-managed keys cannot be tagged
        if m.get("KeyState") not in ("Enabled", "Disabled"):
            continue                      # pending deletion / import etc.
        keys.append((m["Arn"], m["KeyId"]))
    for arn, kid, existing in _tags_for(
            keys,
            lambda a: {t["TagKey"]: t["TagValue"] for t in _collect(
                k.list_resource_tags, "Tags", "Marker", "NextMarker", KeyId=a)},
            "KMS key"):
        missing = missing_tags(existing, STATIC_TAGS)
        evaluate("KMS Key (customer managed)", arn, kid, existing, region, "KMS",
                 lambda _a=arn, _m=missing, _rg=region:
                     _client("kms", region_name=_rg).tag_resource(
                         KeyId=_a,
                         Tags=[{"TagKey": kk, "TagValue": vv} for kk, vv in _m.items()]))


# =============================================================================
# SCANNER REGISTRY
# =============================================================================
_REGIONAL_SCANNER_MAP = {
    "EC2 Instances": scan_ec2_instances, "EBS Volumes": scan_ebs_volumes,
    "EBS Snapshots": scan_ebs_snapshots, "Security Groups": scan_security_groups,
    "VPCs": scan_vpcs, "Subnets": scan_subnets, "Route Tables": scan_route_tables,
    "Internet Gateways": scan_internet_gateways, "NAT Gateways": scan_nat_gateways,
    "Elastic IPs": scan_elastic_ips, "Network Interfaces": scan_network_interfaces,
    "Key Pairs": scan_key_pairs, "AMIs": scan_amis,
    "Lambda Functions": scan_lambda_functions,
    "Load Balancers": scan_load_balancers, "Target Groups": scan_target_groups,
    "ECS Clusters": scan_ecs_clusters, "ECS Services": scan_ecs_services,
    "EKS Clusters": scan_eks_clusters, "DynamoDB Tables": scan_dynamodb_tables,
    "SQS Queues": scan_sqs_queues, "SNS Topics": scan_sns_topics,
    "Secrets Manager": scan_secrets_manager,
    "CloudWatch Log Groups": scan_cloudwatch_log_groups,
    "Kinesis Streams": scan_kinesis_streams, "Step Functions": scan_step_functions,
    "API Gateway (v2)": scan_api_gateway, "ECR Repositories": scan_ecr_repositories,
    "SSM Parameters": scan_ssm_parameters, "Auto Scaling Groups": scan_autoscaling_groups,
    "OpenSearch Domains": scan_opensearch_domains, "MSK Clusters": scan_msk_clusters,
    "SES": scan_ses, "Glue": scan_glue, "KMS (customer managed)": scan_kms,
}

_GLOBAL_SCANNER_MAP = {
    "S3 Buckets": scan_s3_buckets, "IAM Roles": scan_iam_roles,
    "IAM Policies": scan_iam_policies,
    "CloudFront Distributions": scan_cloudfront_distributions,
}


# =============================================================================
# SCAN ORCHESTRATOR (parallel)
# =============================================================================
def _run(label, region, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        err_log(f"{label} in {region}: {e}")


def run_scan(regions: list):
    print(f"\n  Scanning (read-only, no changes), {WORKERS} workers...", flush=True)
    tasks = []
    for label in GLOBAL_SERVICES:
        fn = _GLOBAL_SCANNER_MAP.get(label)
        if fn:
            tasks.append((label, "global", fn, ()))
        else:
            warn_log(f"Unknown global service: {label}")
    for region in regions:
        for label in REGIONAL_SERVICES:
            fn = _REGIONAL_SCANNER_MAP.get(label)
            if fn:
                tasks.append((label, region, fn, (region,)))
            else:
                warn_log(f"Unknown regional service: {label}")
    done = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(_run, *t[:3], *t[3]) for t in tasks]
        for _ in as_completed(futs):
            done += 1
            if done % 25 == 0 or done == len(futs):
                print(f"  Scan progress: {done}/{len(futs)} tasks done", flush=True)
    PLAN.sort(key=lambda p: (p["region"], p["service"], p["type"], str(p["name"])))
    print(f"\n  Scan complete: {EVAL_COUNT[0]} resources checked, {len(PLAN)} need tags, "
          f"{len(ERRORS)} error/warning(s).", flush=True)


# =============================================================================
# PLAN DISPLAY
# =============================================================================
def print_errors():
    if ERRORS:
        section(f"ERRORS / WARNINGS DURING SCAN ({len(ERRORS)})")
        for e in ERRORS:
            print(f"  {e[:200]}", flush=True)


def print_plan():
    print_errors()
    section("TAG PLAN  -  resources that will be modified")
    if not PLAN:
        if ERRORS:
            print("\n  [INCOMPLETE] No tag changes planned, but scan errors occurred. "
                  "Do NOT conclude everything is tagged; fix the errors and rerun.\n",
                  flush=True)
        else:
            print("\n  [OK] Scan completed without errors; no resources need tags.\n",
                  flush=True)
        return

    by_type = defaultdict(int)
    for item in PLAN:
        by_type[item["type"]] += 1
    print("\n  SUMMARY BY RESOURCE TYPE:", flush=True)
    print(f"  {'-' * 46}\n  {'Resource Type':<35}  Count\n  {'-' * 46}", flush=True)
    for rtype, count in sorted(by_type.items()):
        print(f"  {rtype:<35}  {count}", flush=True)
    print(f"  {'-' * 46}\n  {'TOTAL':<35}  {len(PLAN)}", flush=True)

    print("\n\n  FULL RESOURCE LIST:", flush=True)
    W_TYPE, W_NAME, W_REGION, W_TAGS = 30, 34, 14, 24
    print(f"\n  {'#':<5}  {'Resource Type':<{W_TYPE}}  {'Name / ID':<{W_NAME}}  "
          f"{'Region':<{W_REGION}}  Missing Tags", flush=True)
    divider = f"  {'-' * 5}  {'-' * W_TYPE}  {'-' * W_NAME}  {'-' * W_REGION}  {'-' * W_TAGS}"
    print(divider, flush=True)
    for idx, item in enumerate(PLAN, 1):
        keys = ", ".join(item["missing"])
        if len(keys) > W_TAGS:
            keys = keys[:W_TAGS - 3] + "..."
        print(f"  {idx:<5}  {str(item['type'])[:W_TYPE]:<{W_TYPE}}  "
              f"{str(item['name'])[:W_NAME - 1]:<{W_NAME}}  "
              f"{item['region']:<{W_REGION}}  {keys}", flush=True)
    print(divider, flush=True)
    print(f"\n  {len(PLAN)} resource(s) WOULD be tagged (nothing changed yet).\n", flush=True)


# =============================================================================
# APPROVAL GATE
# =============================================================================
def ask_approval() -> bool:
    if AUTO_APPROVE:
        print("  --yes flag set: skipping interactive approval.", flush=True)
        return True
    print("=" * 68, flush=True)
    print("              !!  APPROVAL REQUIRED  !!", flush=True)
    print("\n  No changes have been made yet.", flush=True)
    print("  Type  yes  to apply.  Anything else cancels.", flush=True)
    print("=" * 68 + "\n", flush=True)
    try:
        answer = input("  Apply these changes? (yes/no): ").strip().lower()
    except EOFError:
        print("\n  No interactive input available. Cancelling.", flush=True)
        return False
    return answer == "yes"


# =============================================================================
# PHASE 2 - APPLY (parallel)
# =============================================================================
TRANSIENT_CODES = {
    "Throttling", "ThrottlingException", "ThrottledException", "RequestLimitExceeded",
    "TooManyRequestsException", "RequestThrottled", "RequestTimeout",
    "RequestTimeoutException", "ServiceUnavailable", "InternalError", "InternalFailure",
    "InternalServerError", "ConcurrentModificationException", "OperationAbortedException",
}
FAILURES = []


def _err_code(e):
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", "ClientError")
    return type(e).__name__


def _attempt(item):
    for attempt in range(1, 4):
        try:
            item["apply_fn"]()
            return None
        except Exception as e:
            if _err_code(e) in TRANSIENT_CODES and attempt < 3:
                time.sleep(2 ** attempt)
                continue
            return e
    return None


def apply_plan():
    section("PHASE 2 - APPLYING TAGS")
    total = len(PLAN)
    cnt = {"ok": 0, "fail": 0}

    def work(idx, item):
        err = _attempt(item)
        tags = ", ".join(item["missing"])
        with _LOCK:
            if err is None:
                cnt["ok"] += 1
                print(f"  [{idx}/{total}]  OK      {item['type']}  [{item['name']}]  "
                      f"{item['region']}  +{tags}", flush=True)
            else:
                cnt["fail"] += 1
                FAILURES.append({"item": item, "code": _err_code(err), "msg": str(err)})
                print(f"  [{idx}/{total}]  FAILED  {item['type']}  [{item['name']}]  "
                      f"{item['region']}  {_err_code(err)}", flush=True)

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        list(ex.map(lambda a: work(*a), enumerate(PLAN, 1)))

    print(f"\n  {'=' * 60}", flush=True)
    print(f"  Successfully tagged : {cnt['ok']}", flush=True)
    print(f"  Failed              : {cnt['fail']}", flush=True)
    print(f"  {'=' * 60}", flush=True)
    if FAILURES:
        print_failures()


def print_failures():
    section(f"FAILED RESOURCES ({len(FAILURES)})  -  tags NOT applied")
    by_code = defaultdict(int)
    for f in FAILURES:
        by_code[f["code"]] += 1
    print("\n  FAILURES BY ERROR:", flush=True)
    for code, n in sorted(by_code.items(), key=lambda x: -x[1]):
        print(f"    {n:>5}  {code}", flush=True)
    print("\n  DETAILS:", flush=True)
    for i, f in enumerate(FAILURES, 1):
        it = f["item"]
        print(f"\n  {i}. {it['type']}  [{it['name']}]  region={it['region']}", flush=True)
        print(f"     id     : {it['id']}", flush=True)
        print(f"     tags   : {', '.join(it['missing'])}", flush=True)
        print(f"     error  : {f['code']}", flush=True)
        print(f"     detail : {f['msg'][:400]}", flush=True)
    print("", flush=True)


# =============================================================================
# MAIN
# =============================================================================
def main():
    print("\n" + "=" * 70, flush=True)
    print("  AWS TAG COMPLIANCE CHECKER & AUTO-TAGGER", flush=True)
    print("  Prod-safe mode  -  Scan -> Review Plan -> Approve -> Apply", flush=True)
    print("=" * 70, flush=True)

    try:
        identity = _client("sts").get_caller_identity()
        print(f"\n  AWS Account : {identity['Account']}", flush=True)
        print(f"  Caller ARN  : {identity['Arn']}", flush=True)
    except Exception as e:
        print(f"\n  [FATAL] Cannot authenticate to AWS: {e}", flush=True)
        sys.exit(1)

    regions = get_regions()
    print(f"\n  Scanning {len(regions)} region(s): {', '.join(regions)}", flush=True)
    print(f"  Regional services: {len(REGIONAL_SERVICES)}", flush=True)
    print(f"  Global services:   {len(GLOBAL_SERVICES)}", flush=True)
    print(f"  Workers:           {WORKERS}", flush=True)

    run_scan(regions)
    print_plan()

    if not PLAN:
        sys.exit(2 if ERRORS else 0)

    if not ask_approval():
        print("\n  Apply cancelled. Zero changes were made to your AWS account.\n", flush=True)
        sys.exit(0)

    apply_plan()
    section("ALL DONE")
    print(f"  Resources in plan: {len(PLAN)}\n", flush=True)


if __name__ == "__main__":
    main()
