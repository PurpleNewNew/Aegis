import asyncio
import logging
import ollama
import chromadb
from asyncio import Queue

class AISoftWorker:
    """
    Analyzes contexts for "soft" vulnerabilities using a RAG-powered LLM call.
    """

    def __init__(self, input_q: Queue, output_q: Queue, config: dict):
        self.input_q = input_q
        self.output_q = output_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Initialize Ollama client
        self.ollama_client = ollama.AsyncClient(
            host=self.config['ollama']['host'],
            timeout=self.config['ollama']['timeout']
        )
        
        # Initialize ChromaDB client
        try:
            self.chroma_client = chromadb.PersistentClient(path=self.config['chromadb']['path'])
            self.collection = self.chroma_client.get_or_create_collection(name=self.config['chromadb']['collection_name'])
            self.logger.info(f"Connected to ChromaDB and got collection '{self.config['chromadb']['collection_name']}'.")
        except Exception as e:
            self.logger.error(f"Failed to initialize ChromaDB: {e}", exc_info=True)
            self.chroma_client = None # Disable DB functionality

    def build_prompt(self, context, memories):
        """
        Builds a detailed prompt for the LLM, including context and retrieved memories.
        """
        prompt = f"""You are a web security expert specializing in front-end and business logic vulnerabilities. 
Analyze the following network request for potential security flaws. 
Focus on issues like Cross-Site Scripting (XSS), insecure direct object references (IDOR), authorization flaws, and business logic errors.\n\n--- Current Request Context ---\n\nURL: {context['url']}\n\nMethod: {context['method']}\n\nHeaders: {context['headers']}\n\nPOST Data (Hex): {context['post_data']}\n\n"""

        if memories and memories.get('documents') and memories['documents'][0]:
            prompt += "--- Relevant Historical Analysis (Memories) ---\n"
            for mem in memories['documents'][0]:
                prompt += f"- {mem}\n"
            prompt += "\n"

        prompt += (
            "--- Analysis Task ---\n"
            "1. Identify potential vulnerabilities based on the request data and historical context.\n"
            "2. For each finding, provide a brief explanation of the vulnerability, its potential impact (Severity: Low/Medium/High/Critical), and your Confidence (in percentage).\n"
            "3. If no vulnerabilities are found, state 'No soft vulnerabilities identified.'.\n"
            "4. Format your response clearly."
        )
        return prompt

    async def run(self):
        self.logger.info("AI Soft Worker is running.")
        try:
            while True:
                context = await self.input_q.get()
                self.logger.info(f"Analyzing soft vulnerabilities for: {context['url']}")

                # 1. Retrieve memories from ChromaDB
                memories = None
                if self.chroma_client:
                    try:
                        memories = self.collection.query(query_texts=[context['url']], n_results=3)
                        self.logger.info(f"Retrieved {len(memories.get('documents', [[]])[0])} memories for URL.")
                    except Exception as e:
                        self.logger.error(f"Error querying ChromaDB: {e}")

                # 2. Build the prompt
                prompt = self.build_prompt(context, memories)

                # 3. Generate analysis from Ollama
                try:
                    response = await self.ollama_client.chat(
                        model=self.config['ollama']['model'],
                        messages=[{'role': 'user', 'content': prompt}]
                    )
                    analysis_text = response['message']['content']
                    self.logger.info(f"Ollama analysis received for {context['url']}.")

                    # Log the conversation for debugging
                    await log_ai_dialogue(prompt, analysis_text, self.config['logging']['ai_dialogues_file'])

                    # 4. Package and send the result
                    analysis_result = {
                        'source_context': context,
                        'analysis_text': analysis_text,
                        'worker': self.__class__.__name__
                    }
                    await self.output_q.put(analysis_result)

                except Exception as e:
                    self.logger.error(f"Error communicating with Ollama: {e}")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("AI Soft Worker is shutting down.")
        except Exception as e:
            self.logger.error(f"An error occurred in AISoftWorker: {e}", exc_info=True)