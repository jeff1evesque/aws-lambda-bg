import json
import time
import boto3
import requests
from distutils.util import strtobool
from botocore.exceptions import ClientError

client_api    = boto3.client('apigateway')
client_lambda = boto3.client('lambda')


def log(message, *args, **kwargs):
    '''

    log message to cloudwatch logs.

    '''

    if args or kwargs:
        message = message.format(*args, **kwargs)

    print(message)


def add_permission(function_name, version, source_arn, type='latest'):
    '''

    dynamically add permission to the provided 'source_arn' to invoke the given
        lambda version(s).

    @type, deployment type [blue|green|latest]

    '''

    #
    # local variables
    #
    statement_id = 'lambda-apigw-invoke-{}'.format(type)

    #
    # check permission exists
    #
    try:
        if version == '$LATEST' or type == 'latest':
            permission = client_lambda.get_policy(FunctionName=function_name)

        else:
            permission = client_lambda.get_policy(
                FunctionName=function_name,
                Qualifier=version
            )

        policy    = json.loads(permission['Policy'])
        statement = policy['Statement']

    except ClientError as e:
        if version == '$LATEST' or type == 'latest':
            log(
                'Notice: failed executing client_lambda.get_policy using function {}',
                function_name
            )
        else:
            log(
                'Notice: failed executing client_lambda.get_policy using function {}:{}',
                function_name,
                version
            )
        permission, policy, statement = None, None, None

    policy_found = False
    if permission and policy and statement:
        policy_found = next([True for x in statement if x['Sid'] == statement_id], False)

    #
    # conditionally add permission
    #
    if version != '$LATEST':
        function_name = '{}:{}'.format(function_name, version)

    if not policy_found:
        try:
            client_lambda.add_permission(
                FunctionName=function_name,
                StatementId=statement_id,
                Action='lambda:InvokeFunction',
                Principal='apigateway.amazonaws.com',
                SourceArn=source_arn
            )

        except ClientError as e:
            log(
                'Error: executing client_lambda.add_permission ({}) {}',
                type,
                str(e)
            )


def lambda_handler(event, context, physicalResourceId=None, noEcho=False):
    '''

    custom lambda resource workaround used to associate an event trigger on a
    given lambda function with a desired api gateway (created from a different
    cloudformation parent-stack). Conventional approach utilizes the 'Events'
    property under the 'AWS::Serverless::Function' SAM resource. However, this
    automatically creates an api gateway, if an api gateway is not explicitly
    created in the SAM template. To remove the side-effect (i.e. duplicated api
    gateway), rather than registering the 'Events' property with the serverless
    function in the SAM-child template, the below function will register the
    lambda trigger with the already created api gateway from the parent-stack.

    '''

    properties                       = event['ResourceProperties']
    tracing_enabled                  = bool(strtobool(properties.get('TracingEnabled', 'True')))
    boundary_length                  = int(properties.get('BoundaryLength', 30))
    boundary_character               = properties.get('BoundaryCharacter', '=').strip()
    debug_status                     = bool(strtobool(properties.get('DebugStatus', 'False').capitalize()))
    function_name                    = properties.get('FunctionName').strip()
    stage_name                       = properties.get('StageName', 'primary_stage').strip()
    api_id                           = properties.get('ApiId').strip()
    method_http_method               = properties.get('MethodHttpMethod', 'GET').strip()
    method_authorization_type        = properties.get('MethodAuthorizationType', 'NONE').strip()
    method_response_http_method      = properties.get('MethodResponseHttpMethod', 'GET').strip()
    method_response_status_code      = properties.get('MethodResponseStatusCode', '200')
    integration_http_method          = properties.get('IntegrationHttpMethod', 'POST')
    http_method_common               = properties.get('HttpMethodCommon', 'POST').strip()
    integration_type                 = properties.get('IntegrationType', 'AWS').strip()
    integration_uri                  = properties.get('IntegrationUri', 'http://httpbin.org/robots.txt').strip()
    integration_response_status_code = properties.get('IntegrationResponseStatusCode', '200').strip()
    integration_response_template    = json.loads(
        properties.get(
            'IntegrationResponseTemplate',
            '{"application/json": ""}'
        )
    )
    put_integration_credentials      = properties.get('PutIntegrationCredentials', None)
    method_response_models           = properties.get('MethodResponseModels', {'application/json': 'Empty'})
    canary_percent_traffic           = float(properties.get('CanaryPercentTraffic', 20))
    use_stage_cache                  = bool(strtobool(properties.get('UseStageCache', 'True')))
    path_part                        = properties.get('PathPart', '/').strip()
    source_arn                       = properties.get('SourceArn').strip()
    version_latest                   = properties.get('VersionLatest', '$LATEST').strip()
    version_name_blue                = properties.get('VersionNameBlue', 'blue').strip()
    version_name_green               = properties.get('VersionNameGreen', 'green').strip()
    aliases                          = client_lambda.list_aliases(FunctionName=function_name)['Aliases']
    boundary                         = ''.format(boundary_character * boundary_length)

    #
    # @root_id: resource id obtained to be used relative to '/lambda' path part
    #     defined from earlier SAM template 'AWS::ApiGateway::Resource'
    #
    resource                         = client_api.get_resources(restApiId=api_id)
    root_id                          = [x for x in resource['items'] if x['path'] == '/{}'.format(path_part)][0]['id']

    #
    # x-ray tracing
    #
    if tracing_enabled:
        from aws_xray_sdk.core import xray_recorder
        from aws_xray_sdk.core import patch_all
        patch_all()

    #
    # lambda version: obtain latest version of desired lambda function
    #
    marker = None
    while True:
        if marker:
            response_iterator = client_lambda.list_versions_by_function(
                FunctionName=function_name,
                Marker=marker,
                MaxItems=100
            )

        else:
            response_iterator = client_lambda.list_versions_by_function(
                FunctionName=function_name,
                MaxItems=100
            )

        try:
            marker = response_iterator['NextMarker']

        except KeyError:
            version_blue = response_iterator['Versions'][-1]['Version']
            if len(response_iterator['Versions']) > 1:
                version_blue = response_iterator['Versions'][-2]['Version']
            version_green = response_iterator['Versions'][-1]['Version']

            #
            # blue deployment: create/update alias
            #
            if next(iter(filter(lambda x: x['Name'] == version_blue, aliases)), False):
                update_alias_blue = client_lambda.update_alias(
                    FunctionName=function_name,
                    Name=version_name_blue,
                    FunctionVersion=version_blue,
                    Description='updated {} at version {} (blue)'.format(function_name, version_blue)
                )
                print(boundary)
                log('Notice: update_alias_blue: {}', update_alias_blue)
                print(boundary)

            else:
                create_alias_blue = client_lambda.create_alias(
                    FunctionName=function_name,
                    Name=version_name_blue,
                    FunctionVersion=version_blue,
                    Description='created {} at version {} (blue)'.format(function_name, version_blue)
                )
                print(boundary)
                log('Notice: create_alias_blue: {}', create_alias_blue)
                print(boundary)

            #
            # green deployment: create/update alias
            #
            if next(iter(filter(lambda x: x['Name'] == version_green, aliases)), False):
                client_lambda.get_alias(function_name, version_name_green)
                update_alias_green = client_lambda.update_alias(
                    FunctionName=function_name,
                    Name=version_name_green,
                    FunctionVersion=version_green,
                    Description='updated {} at version {} (green)'.format(function_name, version_green)
                )
                print(boundary)
                log('Notice: update_alias_green: {}', update_alias_green)
                print(boundary)

            else:
                create_alias_green = client_lambda.create_alias(
                    FunctionName=function_name,
                    Name=version_name_green,
                    FunctionVersion=version_green,
                    Description='created {} at version {} (green)'.format(function_name, version_green)
                )
                print(boundary)
                log('Notice: create_alias_green: {}', create_alias_green)
                print(boundary)

            break

    #
    # debug: optional helpful debug statements
    #
    if debug_status:
        print(boundary)
        log('version_blue: {}', version_blue)
        log('version_green: {}', version_green)
        log('method_http_method: {}', method_http_method)
        log('method_response_http_method: {}', method_response_http_method)
        log('integration_uri: {}', integration_uri)
        log('integration_http_method: {}', integration_http_method)
        log('put_integration_credentials: {}', put_integration_credentials)
        log('http_method_common: {}', http_method_common)
        log('restApiId: {}', api_id)
        log('resourceId: {}', root_id)
        log('statusCode: {}', integration_response_status_code)
        log('integration_response_template: {}', integration_response_template)
        log('canary_percent_traffic: {}', canary_percent_traffic)
        log('use_stage_cache: {}', use_stage_cache)
        log('tracing_enabled: {}', tracing_enabled)
        log('source_arn: {}', source_arn)
        log('aliases: {}', aliases)
        print(boundary)

    #
    # api gateway: required step to give source_arn permission to invoke lambda
    #
    add_permission(function_name, version_latest, source_arn, type='latest')
    add_permission(function_name, version_blue, source_arn, type=version_name_blue)
    add_permission(function_name, version_green, source_arn, type=version_name_green)

    #
    # method: add method to an existing resource
    #
    try:
        method = client_api.put_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod=method_http_method,
            authorizationType=method_authorization_type
        )
        put_method = True
        time.sleep(10)

        if debug_status:
            print(boundary)
            log('method: {}', method)
            print(boundary)

    except ClientError as e:
        log('Error: executing client_api.put_method(..): {}', str(e))
        put_method = False

    #
    # integration: set up a method's integration
    #
    # @httpMethod, between client and APIG
    # @integrationHttpMethod, between APIG and backend. This is not required for
    #     lambda integration (but if defined needs to be POST), and required for
    #     HTTP or AWS
    #
    try:
        if put_integration_credentials:
            method_integration = client_api.put_integration(
                credentials=put_integration_credentials,
                restApiId=api_id,
                resourceId=root_id,
                httpMethod=http_method_common,
                type=integration_type,
                uri='{}:${{stageVariables.env}}/invocations'.format(integration_uri),
                integrationHttpMethod=integration_http_method
            )

        else:
            method_integration = client_api.put_integration(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod=http_method_common,
                type=integration_type,
                uri='{}:${{stageVariables.env}}/invocations'.format(integration_uri),
                integrationHttpMethod=integration_http_method
            )

        put_integration = True
        time.sleep(5)

        if debug_status:
            print(boundary)
            log('method_integration: {}', method_integration)
            print(boundary)

    except ClientError as e:
        log('Error: executing client_api.put_integration(..): {}', str(e))
        put_integration = False

    #
    # method response: add MethodResponse to an existing method resource
    #
    try:
        method_response = client_api.put_method_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod=method_response_http_method,
            statusCode=method_response_status_code,
            responseParameters={
                'method.response.header.Access-Control-Allow-Origin': True
            },
            responseModels=json.loads(
                method_response_models
            ) if isinstance(method_response_models, str) else method_response_models
        )
        put_method_response = True
        time.sleep(5)

        if debug_status:
            print(boundary)
            log('method_response: {}', method_response)
            print(boundary)

    except ClientError as e:
        log('Error: executing client_api.put_method_response(..): {}', str(e))
        put_method_response = False

    #
    # integration response: represents a put integration
    #
    # @responseParameters, enables CORS when the header access is defined via
    #     'method.response.header.Access-Control-Allow-Origin'
    #
    try:
        integration_response = client_api.put_integration_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod=http_method_common,
            statusCode=integration_response_status_code,
            responseTemplates=integration_response_template,
            responseParameters={
                'method.response.header.Access-Control-Allow-Origin': '\'*\''
            }
        )
        put_integration_response = True
        time.sleep(5)

        if debug_status:
            print(boundary)
            log('integration_response: {}', integration_response)
            print(boundary)

    except ClientError as e:
        log('Error: executing client_api.put_integration_response(..): {}', str(e))
        put_integration_response = False

    #
    # base deployment: primary stage (equivalent to blue/stable stage)
    #
    try:
        stage = client_api.get_stage(restApiId=api_id, stageName=stage_name)

    except ClientError as e:
        print(boundary)
        log("Notice: executing client_api.get_stage(..): {}", str(e))
        print(boundary)
        stage = None

    create_deployment = False
    if not (stage and 'canarySettings' in stage):
        try:
            response_create_deployment = client_api.create_deployment(
                restApiId=api_id,
                stageName=stage_name,
                stageDescription='primary stage',
                description='base deployment',
                tracingEnabled=tracing_enabled,
                variables={
                    'env': version_name_blue
                }
            )
            create_deployment = True
            time.sleep(30) # avoid too many requests

            if debug_status:
                print(boundary)
                log('response_create_deployment: {}', response_create_deployment)
                print(boundary)

        except ClientError as e:
            print(boundary)
            log("Notice: executing client_api.create_deployment(..): {}", str(e))
            print(boundary)
            create_deployment = False

    #
    # canary deployment: new stage (equivalent to green/new stage)
    #
    # @variables, inheritted from the base deployment configuration
    # @tracingEnabled, inheritted from the base deployment configuration
    #
    try:
        response_create_deployment_canary = client_api.create_deployment(
            restApiId=api_id,
            stageName=stage_name,
            stageDescription='canary stage',
            description='canary deployment',
            canarySettings={
                'percentTraffic': canary_percent_traffic,
                'stageVariableOverrides': {
                    'env': version_name_green
                },
                'useStageCache': use_stage_cache
            }
        )
        create_deployment_canary = True

        if debug_status:
            print(boundary)
            log('response_create_deployment_canary: {}', response_create_deployment_canary)
            print(boundary)

    except ClientError as e:
        print(boundary)
        log("Error: executing client_api.create_deployment(..): {}", str(e))
        print(boundary)
        create_deployment_canary = False

    #
    # return condition: lambda invoked by cloudformation
    #
    if 'StackId' in event:
        responseUrl = event['ResponseURL']

        log(responseUrl)

        responseBody = {}
        responseBody['Status'] = 'SUCCESS'
        responseBody['Reason'] = '{a}: {b}'.format(
            a='See the details in CloudWatch Log Stream',
            b=context.log_stream_name
        )
        responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
        responseBody['StackId'] = event['StackId']
        responseBody['RequestId'] = event['RequestId']
        responseBody['LogicalResourceId'] = event['LogicalResourceId']
        responseBody['NoEcho'] = noEcho

        responseBody['Data'] = {
            'put_method': put_method,
            'put_method_response': put_method_response,
            'put_integration': put_integration,
            'put_integration_response': put_integration_response,
            'create_deployment': create_deployment,
            'create_deployment_canary': create_deployment_canary
        }

        json_responseBody = json.dumps(responseBody)

        log('Response body:\n{}', json_responseBody)

        headers = {
            'content-type': '',
            'content-length': str(len(json_responseBody))
        }

        try:
            response = requests.put(
                responseUrl,
                data=json_responseBody,
                headers=headers
            )
            log('Status code: {}', response.reason)

        except Exception as e:
            log('send(..) failed executing requests.put(..): {}', str(e))

    #
    # return condition: lambda invoked by something else
    #
    else:
        return {
            'put_method': put_method,
            'put_method_response': put_method_response,
            'put_integration': put_integration,
            'put_integration_response': put_integration_response,
            'create_deployment': create_deployment,
            'create_deployment_canary': create_deployment_canary
        }

if __name__ == '__main__':
    lambda_handler()

