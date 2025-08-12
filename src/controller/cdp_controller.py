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

    async def setup_page_listeners(self, page: Page):
        """Attaches all necessary event listeners to a given page."""
        try:
            self.logger.info(f"Setting up listeners for page: {await page.title()}")
            page.on("request", self.handle_request)
            # You can add more listeners here, e.g., for responses, console logs, etc.
            # page.on("response", self.handle_response)
        except Exception as e:
            self.logger.error(f"Failed to set up listeners for page. It might have closed. Error: {e}")

    async def run(self):
        """
        Connects to the browser, attaches listeners to existing and new pages,
        and keeps running to monitor all activity.
        """
        self.logger.info(f"Attempting to connect to Chrome on port {self.port}...")
        async with async_playwright() as p:
            try:
                browser = await p.chromium.connect_over_cdp(f"http://localhost:{self.port}")
                self.logger.info("Successfully connected to Chrome.")
                
                context = browser.contexts[0]

                # 1. Set up listeners for all currently open pages
                for page in context.pages:
                    await self.setup_page_listeners(page)

                # 2. Set up a listener for any new pages that are created
                context.on("page", self.setup_page_listeners)

                self.logger.info("CDP Controller is now monitoring all current and future pages.")
                
                # Keep the task alive to listen for events
                while browser.is_connected():
                    await asyncio.sleep(1)

            except (ConnectionRefusedError, asyncio.TimeoutError):
                self.logger.error(
                    f"Connection to Chrome on port {self.port} failed. "
                    f"Please ensure Chrome is running with '--remote-debugging-port={self.port}'."
                )
            except Exception as e:
                self.logger.error(f"An unexpected error occurred in CDPController: {e}", exc_info=True)
            finally:
                self.logger.info("CDP Controller has shut down.")
                if 'browser' in locals() and browser.is_connected():
                    await browser.close()