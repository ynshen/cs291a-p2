# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def get_downcase_key(hash:, key:)
    begin
        selected = hash.select {|k, v| k.downcase == key}
        return selected.values[0]
    rescue
        return false
    end
end

def main(event:, context:)
    # You shouldn't need to use context, but its fields are explained here:
    # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html

    if event['path']  == '/token'
        if event['httpMethod'] == 'POST'
            if get_downcase_key(hash: event['headers'], key: 'content-type') == 'application/json'
                # try to parse, return 422 if fail
                begin
                    # Valid POST on /token with JOSN
                    request_body = JSON.parse(event['body'])
                    payload = {
                          data: request_body,
                          exp: Time.now.to_i + 5,
                          nbf: Time.now.to_i + 2
                      }
                    token = JWT.encode payload, ENV["JWT_SECRET"], "HS256"
                    response_body = {"token" => token}
                    return response(body:response_body, status: 201)
                rescue JSON::ParserError
                    return response(status: 422)
                rescue TypeError
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
            auth = get_downcase_key(hash: event['headers'], key: 'authorization')
            if auth != false
                if (auth.is_a? String) and (auth.include? "Bearer") and (auth[0..6] == 'Bearer ')
                    token = auth[7..-1]
                    begin
                        decoded = JWT.decode token, ENV['JWT_SECRET'], true, {algorithm: 'HS256'}
                        response_body = decoded[0]['data']
                        return response(body: response_body, status: 200)
                    rescue JWT::ImmatureSignature
                        return response(status: 401)
                    rescue JWT::DecodeError
                        return response(status: 403)
                    rescue JWT::ExpiredSignature
                        return response(status: 401)
                    end
                else
                    response(status: 403)
                end
            else
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
               'body' => '{}',
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
