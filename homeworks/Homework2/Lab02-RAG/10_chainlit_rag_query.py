import os
import readline
from pathlib import Path
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_chroma import Chroma
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
import chainlit as cl

# Load the shared API keys/model names from the course repo root's .env file
# (gensec-mclean-z23569229/.env), four levels up from this script.
load_dotenv(Path(__file__).resolve().parents[3] / ".env")

# Configure the chat model used by the Chainlit RAG app.
llm = ChatGoogleGenerativeAI(model=os.getenv("GOOGLE_MODEL"))

# Open the persisted vector database and create a retriever from it.
vectorstore = Chroma(
     persist_directory="./rag_data/.chromadb",
     embedding_function=GoogleGenerativeAIEmbeddings(model="models/gemini-embedding-001", task_type="retrieval_query")
)

retriever = vectorstore.as_retriever()

# A local, trusted RAG prompt instead of hub.pull("rlm/rag-prompt"): pulling
# a prompt by owner/name from LangChain Hub now raises ValueError by default
# ("prompts may contain untrusted serialized LangChain objects"), and
# bypassing that check with dangerously_pull_public_prompt=True is exactly
# the kind of deserialization risk it's warning about.
prompt = ChatPromptTemplate.from_template(
    "You are an assistant for question-answering tasks. Use the following "
    "pieces of retrieved context to answer the question. If you don't know "
    "the answer, just say that you don't know. Use three sentences maximum "
    "and keep the answer concise.\n\n"
    "Question: {question}\n\n"
    "Context: {context}\n\n"
    "Answer:"
)

def format_docs(docs):
    """Join retrieved document contents into one prompt context string."""
    # Combine retrieved documents into the context string expected by the prompt.
    return "\n\n".join(doc.page_content for doc in docs)

# Retrieve context, fill the prompt, call the model, and parse plain text.
rag_chain = (
    {"context": retriever | format_docs, "question": RunnablePassthrough()}
    | prompt
    | llm
    | StrOutputParser()
)

@cl.on_chat_start
async def on_chat_start():
    """Send the initial Chainlit logo and welcome message."""
    # Send branding and a short welcome when the Chainlit session opens.
    logo = cl.Image(name="logo", display="inline", url="https://codelabs.cs.pdx.edu/images/pdx-cs-logo.png")
    await cl.Message(content="", elements=[logo]).send()

    welcome_text = (
        "**Welcome to the PSU Generative Security Chatbot!**\n\n"
        "Ask me anything from my set of documents.\n\n"
    )
    await cl.Message(content=welcome_text).send()

@cl.on_message
async def on_message(message: cl.Message):
    """Handle a Chainlit user message by returning a RAG answer."""
    # Answer each chat message through the RAG chain.
    user_query = message.content
    answer = rag_chain.invoke(user_query)
    await cl.Message(content=answer).send()

if __name__ == "__main__":
    cl.run()
