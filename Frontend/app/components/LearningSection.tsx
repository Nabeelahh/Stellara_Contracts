import Image from "next/image";

export default function LearningSection() {
    return (
        <article className="flex flex-col justify-center w-full items-center px-6">
            <section className="pl-6 bg-[url(/images/learningSection.jpg)] bg-cover max-w-7xl rounded-t-4xl pt-30 pb-20 relative before:absolute before:w-full before:h-[30%] before:bottom-0 before:left-0 before:bg-linear-to-b before:from-transparent before:to-[#18151C] before:z-2 sm:flex sm:items-center sm:justify-between w-full sm:gap-5">
                <div className="mb-8 sm:mb-0">
                    <h2 className="font-serif text-3xl sm:text-4xl lg:text-[3.25rem] lg:leading-[1.15] font-light leading-tight tracking-tight text-white my-5">
                        Power the Future of Crypto Learning with Stellara AI
                    </h2>
                    <p className="font-normal text-base sm:text-lg">
                        An intelligent Web3 crypto academy on Stellar, blending
                        AI-driven learning, social collaboration, and real
                        on-chain trading for the next generation of crypto
                        users.
                    </p>
                </div>
                <Image
                    src="/images/learning.png"
                    alt="networks"
                    width={546}
                    height={100}
                    className=" object-cover border-2"
                />
            </section>
        </article>
    );
}
