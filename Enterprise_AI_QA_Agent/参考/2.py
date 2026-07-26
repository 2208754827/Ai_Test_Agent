from openai import OpenAI

client = OpenAI(
    base_url='https://api-inference.modelscope.cn/v1',
    api_key='ms-aacc6c05-74a0-438b-a65a-b94407b5659a', # ModelScope Token
)

response = client.embeddings.create(
    model='Qwen/Qwen3-Embedding-8B', # ModelScope Model-Id, required
    input='你好',
    encoding_format="float"
)

print(response.data)