import asyncio
import logging
from asyncio import Queue
from playwright.async_api import async_playwright, Playwright, Browser, Page

class CDPController:
    """
    Connects to a running Chrome instance via its remote debugging port using Playwright,
    and streams network events into a queue for further processing.
    """

    def __init__(self, output_q: Queue, config: dict):
        """
        Initializes the controller.

        Args:
            output_q: The queue to which raw CDP events will be sent.
            config: The application configuration dictionary.
        """
        self.output_q = output_q
        self.port = config['browser']['remote_debugging_port']
        self.logger = logging.getLogger(self.__class__.__name__)

    async def handle_request(self, request):
        """
        Event handler for 'request' events.
        Puts a structured event into the output queue.
        """
        try:
            event = {
                'event_type': 'request',
                'method': request.method,
                'url': request.url,
                'headers': await request.all_headers(),
                'post_data': request.post_data_buffer.hex() if request.post_data_buffer else None
            }
            await self.output_q.put(event)
            self.logger.info(f"Captured request: {event['method']} {event['url']}")
        except Exception as e:
            self.logger.error(f"Error handling request event for {request.url}: {e}")

    async def run(self):
        """
        The main loop for the controller. Connects to the browser and sets up event listeners.
        """
        self.logger.info(f"Attempting to connect to Chrome on port {self.port}...")
        async with async_playwright() as p:
            try:
                browser = await p.chromium.connect_over_cdp(f"http://localhost:{self.port}")
                self.logger.info("Successfully connected to Chrome.")
                
                # Get the first context (usually the default one)
                context = browser.contexts[0]
                page = context.pages[0]
                self.logger.info(f"Attached to page: {await page.title()}")

                # Set up event listeners
                page.on("request", self.handle_request)
                # You can add more listeners here, e.g., for responses, console logs, etc.
                # page.on("response", self.handle_response)

                self.logger.info("CDP Controller is running and listening for events.")
                
                # Keep the task alive to listen for events
                while True:
                    await asyncio.sleep(3600) # Sleep for a long time

            except (ConnectionRefusedError, asyncio.TimeoutError):
                self.logger.error(
                    f"Connection to Chrome on port {self.port} failed. "
                    f"Please ensure Chrome is running with '--remote-debugging-port={self.port}'."
                )
            except IndexError:
                 self.logger.error(
                    f"Could not find a page to attach to. Please ensure a tab is open in the target browser."
                )
            except Exception as e:
                self.logger.error(f"An unexpected error occurred in CDPController: {e}")
            finally:
                if 'browser' in locals() and browser.is_connected():
                    await browser.close()
                self.logger.info("CDP Controller has shut down.")