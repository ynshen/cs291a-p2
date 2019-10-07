# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
    # You shouldn't need to use context, but its fields are explained here:
    # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html

    if event['path']  == '/token'
        if event['httpMethod'] == 'POST'
            if event['headers']['Content-Type'] == 'application/json'
                # try to parse, return 422 if fail
                begin
                    # Valid POST on /token with JOSN
                    # TODO: check this part for requirement
                    request_body = JSON.parse(event['body']) #suppose to be another hash?
                    payload = {
                          data: request_body,
                          exp: Time.now.to_i + 5,
                          nbf: Time.now.to_i + 2
                      }
                    token = JWT.encode payload, ENV["JWT_SECRET"], "HS256"
                    response_body = {"token" => token}
                    return response(body:response_body, status: 201)
                rescue JSON::ParserError => e
                    return response(status: 422)
                end
            else
                return response(status: 415)
            end
        else
            response(status: 405)
        end
    elsif event['path'] == '/'
        if event['httpMethod'] == 'GET'
            if event['headers'].key?('Authorization')
                #puts event['headers']['Authorization']
                #puts event['headers']['Authorization'][0..6]
                if event['headers']['Authorization'][0..6] == 'Bearer '
                    token = event['headers']['Authorization'][7..-1]
                    #puts token
                    begin
                        decoded = JWT.decode token, ENV['JWT_SECRET'], true, {algorithm: 'HS256'}
                        response_body = decoded[0]['data']
                        return response(body: response_body, status: 200)
                    rescue JWT::ImmatureSignature
                        return response(status: 401)
                    rescue JWT::ExpiredSignature
                        return response(status: 401)
                    end
                else
                    #puts 'Bearer failed'
                    response(status: 403)
                end
            else
                #puts "Nno Authorization"
                response(status: 403)
            end
        else
            response(status: 405)
        end
    else
        response(status: 404)
    end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
