import os
import openai

class LLMInterface:
    """ API 호출을 위한 인터페이스"""
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key not found. Please set the LLM_API_KEY environment variable.")
        
        try:
            self.client = openai.OpenAI(api_key=self.api_key)
            print("LLMInterface initialized with actual OpenAI client")
        except Exception as e:
            print(f"Failed to initialize OpenAI client: {e}")
            raise

    def generate_text(self, prompt: str, temperature: float = 0.4) -> str:
        """주어진 프롬프트를 바탕으로 OpenAI Chat Completion API를 호출합니다."""
        print(f"--- Calling OpenAI API (temp={temperature}) ---\n{prompt[:300]}...\n")
        
        try:
            response = self.client.chat.completions.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), 
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=temperature,
            )
            content = response.choices[0].message.content
            print(f"--- OpenAI API Response ---\n{content}\n")
            return content.strip() if content else ""
        except openai.APIConnectionError as e:
            print(f"OpenAI API Connection Error: {e.__cause__}")
        except openai.RateLimitError as e:
            print(f"OpenAI API Rate Limit Error: {e.response.status_code} {e.response.text}")
        except openai.APIStatusError as e:
            print(f"OpenAI API Status Error: {e.status_code} - {e.response}")
        except Exception as e:
            print(f"An unexpected error occurred with the OpenAI API: {e}")
        
        return "" # 오류 발생 시 빈 문자열 반환