import asyncio
import logging
import chromadb
import hashlib
from asyncio import Queue

class MemoryWorker:
    """
    Pulls final analysis results and stores the key takeaways (the AI's analysis)
    as memories in a ChromaDB vector database for future RAG retrieval.
    """

    def __init__(self, input_q: Queue, config: dict):
        """
        Initializes the worker.

        Args:
            input_q: The queue from which to pull final analysis results.
            config: The application configuration dictionary.
        """
        self.input_q = input_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        try:
            self.chroma_client = chromadb.PersistentClient(path=self.config['chromadb']['path'])
            self.collection = self.chroma_client.get_or_create_collection(name=self.config['chromadb']['collection_name'])
            self.logger.info(f"Connected to ChromaDB and got collection '{self.config['chromadb']['collection_name']}'.")
        except Exception as e:
            self.logger.error(f"Failed to initialize ChromaDB: {e}", exc_info=True)
            self.chroma_client = None # Disable DB functionality

    def create_memory_id(self, text: str) -> str:
        """
        Creates a consistent, unique ID for a memory document.
        """
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    async def run(self):
        """
        The main loop for the worker.
        It continuously pulls results and stores them as memories.
        """
        if not self.chroma_client:
            self.logger.warning("ChromaDB not initialized. MemoryWorker will not run.")
            return

        self.logger.info("Memory Worker is running.")
        try:
            while True:
                result = await self.input_q.get()
                self.logger.debug(f"Received result for memorization from {result.get('worker')}")

                # Create a concise memory document from the result.
                source_context = result.get('source_context', {})
                analysis_text = result.get('analysis_text', '')
                
                # We only want to memorize actual findings, not "no vulnerability" messages.
                if "no vulnerabilities identified" in analysis_text.lower() or not analysis_text:
                    self.logger.info("Skipping memorization for non-finding.")
                    self.input_q.task_done()
                    continue

                memory_doc = (
                    f"When analyzing the URL '{source_context.get('url')}' with the method '{source_context.get('method')}', "
                    f"the following analysis was produced: {analysis_text}"
                )
                
                memory_id = self.create_memory_id(memory_doc)

                try:
                    # Add the document to the collection. ChromaDB handles embedding.
                    # Using `add` with the same ID will update the existing entry if you use a newer version of chromadb that supports it,
                    # or raise an error in older versions. Here we assume we want unique memories.
                    self.collection.add(
                        ids=[memory_id],
                        documents=[memory_doc],
                        metadatas=[{'source_url': source_context.get('url')}] # Optional metadata
                    )
                    self.logger.info(f"Successfully stored new memory (ID: {memory_id[:8]}...) for URL {source_context.get('url')}.")
                except Exception as e:
                    # This might happen if we try to add a duplicate ID, which is fine.
                    self.logger.warning(f"Could not store memory (it might already exist): {e}")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("Memory Worker is shutting down.")
        except Exception as e:
            self.logger.error(f"An error occurred in MemoryWorker: {e}", exc_info=True)